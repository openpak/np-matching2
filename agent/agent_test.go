// The handshake through the agent against a real Postgres (NP_MATCHING_TEST_DATABASE_URL) with the headless client:
// ping, login with a real ticket, world list from a fake core, renew, MAC refusals, erasure. Skipped without a database.
package agent_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"openpak/np-common/ticket"
	"openpak/np-matching2/agent"
	"openpak/np-matching2/client"
	"openpak/np-matching2/wire"
)

type fakeRooms struct {
	created, left, data int
	beats               []string
	endpoints           map[string][]byte // account -> published address
	events              chan agent.RoomEvent
}

func (f *fakeRooms) SetEndpoints(_ context.Context, _, account string, addr []byte, _ byte) error {
	if f.endpoints == nil {
		f.endpoints = map[string][]byte{}
	}
	f.endpoints[account] = addr
	return nil
}
func (f *fakeRooms) Members(context.Context, string, string) ([]agent.RoomMember, error) {
	return []agent.RoomMember{{No: 1, Account: "11111111-1111-1111-1111-111111111111"}, {No: 2, Account: "33333333-3333-3333-3333-333333333333", Addr: []byte{10, 1, 2, 3}, NAT: 2}}, nil
}
func (f *fakeRooms) Watch(ctx context.Context, _ string, fn func(agent.RoomEvent)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev := <-f.events:
			fn(ev)
		}
	}
}

func (f *fakeRooms) CreateRoom(_ context.Context, title, account string, max uint32, data []byte) (*agent.Room, error) {
	f.created++
	return &agent.Room{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", RoomID: 0xaaaaaaaabbbbcccc, MemberNo: 1}, nil
}
func (f *fakeRooms) LeaveRoom(context.Context, string, string) error { f.left++; return nil }
func (f *fakeRooms) SetRoomData(context.Context, string, string, []byte) error {
	f.data++
	return nil
}
func (f *fakeRooms) Heartbeat(_ context.Context, account string) { f.beats = append(f.beats, account) }
func (f *fakeRooms) SearchRooms(context.Context, string, string, []string, uint32) ([]agent.RoomInfo, error) {
	return []agent.RoomInfo{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", RoomID: 0x0001aaaaaaaabbbb, Owner: "33333333-3333-3333-3333-333333333333", Network: "np", Max: 4, Members: 1}}, nil
}
func (f *fakeRooms) JoinRoom(_ context.Context, _ string, account string) (*agent.JoinedRoom, error) {
	return &agent.JoinedRoom{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", RoomID: 0x0001aaaaaaaabbbb, MemberNo: 2, Max: 4, Members: []agent.RoomMember{{No: 1, Account: "33333333-3333-3333-3333-333333333333"}, {No: 2, Account: account}}}, nil
}

type fakeCore struct{ rooms, members uint32 }

func (f fakeCore) Worlds(context.Context, string, []string) (uint32, uint32, error) {
	return f.rooms, f.members, nil
}

func TestHandshake(t *testing.T) {
	url := os.Getenv("NP_MATCHING_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("NP_MATCHING_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	st, err := agent.OpenStore(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.DB.Exec(ctx, `TRUNCATE m2_sessions`)
	st.DB.Exec(ctx, `TRUNCATE m2_room_keys`)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ticket.New(priv, nil)
	pass := make([]byte, 128)
	rand.Read(pass)
	const acct = "11111111-1111-1111-1111-111111111111"
	fr := &fakeRooms{events: make(chan agent.RoomEvent, 1)}
	a := &agent.Agent{RoomEvents: true, Titles: map[string]agent.Title{"NPWR04270_00": {Key: "terraria", Pass: pass}}, Store: st, Tickets: signer, Core: fakeCore{rooms: 3, members: 5}, Rooms: fr}

	// loopback TCP, not net.Pipe: the agent now writes without being asked (keepalive echoes, events), which an unbuffered pipe deadlocks
	pair := func(h func(net.Conn)) net.Conn {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			if s, err := ln.Accept(); err == nil {
				h(s)
			}
		}()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := &client.Client{Comm: "NPWR04270_00", Pass: pass, Plain: pair(a.ServePlain), TLS: pair(a.ServeTLS)}

	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(wire.CmdWorldList); err == nil {
		t.Fatal("a request before login must not be answered")
	}
	tk, err := signer.Issue(ticket.Identity{AccountID: acct, LinkID: "l", OnlineID: "PS3Test", Country: "pt", Service: "IV0001-NPXS01001_00"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Login(tk, "PS3Test", "PS3 Test User"); err != nil || len(c.Key) != 20 {
		t.Fatalf("login: %v", err)
	}

	// the login keeps the account's room membership alive without any room-server connection
	fr.beats = nil
	if n := a.HeartbeatActive(ctx); n != 1 || len(fr.beats) != 1 || fr.beats[0] != acct {
		t.Fatalf("heartbeat: %d %v", n, fr.beats)
	}

	// a fresh plain connection finds the session by its MAC
	c.Plain = pair(a.ServePlain)
	c.Plain.Write([]byte{0})
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	f, err := c.Call(wire.CmdWorldList)
	if err != nil {
		t.Fatal(err)
	}
	w := f.Elements()[0x02]
	if len(w) < 4+4+18 || w[3] != 1 || w[4+4+12] != 0 || w[4+4+13] != 3 {
		t.Fatalf("world list %x", w)
	}
	if f, err = c.Call(wire.CmdRenew); err != nil || len(f.Elements()[0x5d]) != 16 {
		t.Fatalf("renew: %v", err)
	}

	// A real console logs in again and sends the next request, signed with the new key, on the plain
	// connection the agent already pinned to the first login (real PS3, 2026-11-07: the 0x1209 was
	// dropped as "no session for request"). The agent must re-resolve, not verify against the stale key.
	firstKey := append([]byte(nil), c.Key...)
	if _, err := c.Login(tk, "PS3Test", "PS3 Test User"); err != nil || len(c.Key) != 20 || bytes.Equal(c.Key, firstKey) {
		t.Fatalf("second login: %v", err)
	}
	pf, err := c.Call(wire.CmdUnknown1209, wire.TLV(0x29, 4, []byte{0, 1}))
	if err != nil || len(pf.Elements()[0x20]) == 0 {
		t.Fatalf("0x1209 after second login on the pinned plain connection: %v", err)
	}

	// a plain keepalive is answered with one (the firmware drops an agent connection the server leaves silent for ~20 s)
	c.Plain.Write([]byte{0})
	kb := make([]byte, 1)
	c.Plain.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := c.Plain.Read(kb); err != nil || n != 1 || kb[0] != 0 {
		t.Fatalf("keepalive echo: %v %x", err, kb)
	}

	// room flow: 0x3200 creates a room and answers the five required elements; 0x1202 updates, 0x3202 leaves
	rf, err := c.Call(0x3200, wire.TLV(0x3f, 4, []byte{0, 4}), wire.TLV(0x13, 0, []byte{2}), wire.TLV(0x6e, 2, []byte{37, 228, 205, 125}))
	if err != nil {
		t.Fatal(err)
	}
	el := rf.Elements()
	for _, id := range []uint16{0x24, 0x3a, 0x21, 0x71, 0x4b} {
		if len(el[id]) == 0 {
			t.Fatalf("0x3200 reply lacks element 0x%x", id)
		}
	}
	if fr.created != 1 || len(el[0x3a]) != 8 || el[0x3a][0] != 0xaa {
		t.Fatalf("room %v %x", fr, el[0x3a])
	}
	// the console's own address is published in the core and echoed in its member; both tokens carry the stored room key
	if a := fr.endpoints[acct]; len(a) != 4 || a[0] != 37 {
		t.Fatalf("endpoint %v", fr.endpoints)
	}
	var roomKey []byte
	st.DB.QueryRow(ctx, `SELECT key FROM m2_room_keys WHERE account=$1`, acct).Scan(&roomKey)
	for _, id := range []uint16{0x24, 0x21} {
		if k, err := wire.RoomKeyFromToken(c.Key, el[id]); err != nil || len(roomKey) != 16 || string(k) != string(roomKey) {
			t.Fatalf("token 0x%x does not carry the room key: %v", id, err)
		}
	}
	if !bytes.Contains(el[0x4b], []byte{0x20, 0x6e, 0x00, 0x04, 37, 228, 205, 125}) || !bytes.Contains(el[0x4b], []byte{2, 0}) {
		t.Fatalf("member lacks the address/nat: %x", el[0x4b])
	}

	// a room event for this console reaches its plain connection, MAC'd with its room key
	fr.events <- agent.RoomEvent{Type: "member_joined", Session: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Subject: "33333333-3333-3333-3333-333333333333", To: acct, MemberNo: 2}
	ef, err := client.ReadFrame(c.Plain)
	if err != nil || ef.Kind != wire.KindEvent || ef.Cmd != wire.EventMemberJoined || !ef.Verify(roomKey) {
		t.Fatalf("event: %v %+v", err, ef)
	}
	if ev := ef.Raw; binary.BigEndian.Uint64(ev[8:16]) != 0x0001aaaaaaaabbbb || !bytes.Contains(ef.Elements()[0x4b], []byte{10, 1, 2, 3}) {
		t.Fatalf("event room id / joiner address: %x", ef.Raw)
	}

	sf, err := c.Call(0x1200)
	if err != nil || len(sf.Elements()[0x03]) < 8+4+0x24+36 {
		t.Fatalf("search: %v %x", err, sf.Elements()[0x03])
	}
	jf, err := c.Call(0x3201, wire.TLV(0x3e, 4, []byte{0xbb, 0xbb}))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint16{0x16, 0x24, 0x3a, 0x21, 0x71, 0x02} {
		if len(jf.Elements()[id]) == 0 {
			t.Fatalf("0x3201 reply lacks 0x%x", id)
		}
	}
	if _, err := c.Call(0x1202, wire.TLV(0x3a, 2, el[0x3a])); err != nil || fr.data != 1 {
		t.Fatalf("0x1202: %v %d", err, fr.data)
	}
	// the firmware MACs 0x3202 with its room key, on a fresh connection that names nobody; the reply carries the same key
	// (the join above replaced this member's key for the room)
	st.DB.QueryRow(ctx, `SELECT key FROM m2_room_keys WHERE account=$1`, acct).Scan(&roomKey)
	c.Plain = pair(a.ServePlain)
	c.Plain.Write([]byte{0})
	c.Ping()
	lf, err := c.CallKey(roomKey, 0x3202, wire.TLV(0x28, 0, []byte{0}))
	if err != nil || fr.left != 1 {
		t.Fatalf("0x3202 with the room key: %v %d", err, fr.left)
	}
	if !lf.Verify(roomKey) {
		t.Fatal("0x3202 reply not MAC'd with the room key")
	}

	// a stranger's key is not answered; a wrong passphrase cannot log in
	bad := &client.Client{Comm: "NPWR04270_00", Pass: pass, Plain: pair(a.ServePlain), Key: make([]byte, 20)}
	bad.Plain.Write([]byte{0})
	if _, err := bad.Call(wire.CmdWorldList); err == nil {
		t.Fatal("unknown key answered")
	}
	wrong := &client.Client{Comm: "NPWR04270_00", Pass: append([]byte{1}, pass[1:]...), TLS: pair(a.ServeTLS)}
	if _, err := wrong.Login(tk, "PS3Test", "x"); err == nil {
		t.Fatal("login with the wrong passphrase")
	}

	// erasure
	t.Setenv("ACCOUNT_ERASE_KEY", "k")
	mux := http.NewServeMux()
	a.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest("DELETE", srv.URL+"/internal/accounts/"+acct+"/data", nil)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 401 {
		t.Fatal("erase needs the key")
	}
	req.Header.Set("Authorization", "Bearer k")
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 200 {
		t.Fatal("erase")
	}
	var n int
	st.DB.QueryRow(ctx, `SELECT count(*) FROM m2_sessions WHERE account=$1`, acct).Scan(&n)
	if n != 0 {
		t.Fatal("sessions survive erasure")
	}
}
