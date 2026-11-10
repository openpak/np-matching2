package agent_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"openpak/np-common/ticket"
	"openpak/np-matching2/agent"
	"openpak/np-matching2/client"
	"openpak/np-matching2/wire"
)

// The Minecraft PS3 01.84 hosting and joining sequence through the agent, a real Postgres (NP_MATCHING_TEST_DATABASE_URL) and a real matchmaking
// core (NP_MATCHING_TEST_CORE_ADDR/KEY): the server status, room creation with the two internal bins and the member's 0x59, the external bins and
// ints, GetRoomDataExternalList, SearchRoom with an int filter, JoinRoom, the update commands and their events, member read and kickout.
// Request layouts are the firmware builders' (research matching2-protocol.md §6), not a console capture.
func TestMinecraftHostAndJoin(t *testing.T) {
	url, addr := os.Getenv("NP_MATCHING_TEST_DATABASE_URL"), os.Getenv("NP_MATCHING_TEST_CORE_ADDR")
	if url == "" || addr == "" {
		t.Skip("needs NP_MATCHING_TEST_DATABASE_URL and NP_MATCHING_TEST_CORE_ADDR")
	}
	ctx := context.Background()
	st, err := agent.OpenStore(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.DB.Exec(ctx, `TRUNCATE m2_sessions`)
	st.DB.Exec(ctx, `TRUNCATE m2_room_keys`)
	mm, conn, err := agent.DialMatchmaking(addr, os.Getenv("NP_MATCHING_TEST_CORE_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ticket.New(priv, nil)
	pass := make([]byte, 128)
	rand.Read(pass)
	const comm, hostAcct, joinAcct = "NPWR05636_00", "aaaaaaaa-0000-0000-0000-000000000001", "aaaaaaaa-0000-0000-0000-000000000002"
	a := &agent.Agent{RoomEvents: true, Titles: map[string]agent.Title{comm: {Key: "mc-e2e", Pass: pass, Compat: "lce-ps3-0884", Status: 1}}, Store: st, Tickets: signer, Core: mm, Rooms: mm}
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
	login := func(acct, online string) *client.Client {
		c := &client.Client{Comm: comm, Pass: pass, Plain: pair(a.ServePlain), TLS: pair(a.ServeTLS)}
		pf, err := c.Ping()
		if err != nil {
			t.Fatal(err)
		}
		if got := pf.Elements()[0x1d]; !bytes.Equal(got, []byte{0, 1, 1}) {
			t.Fatalf("0x1001 element 0x1d = %x, want server 1 status 1", got)
		}
		tk, err := signer.Issue(ticket.Identity{AccountID: acct, LinkID: "l", OnlineID: online, Country: "pt", Service: "IV0001-NPXS01001_00"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Login(tk, online, "pt", online); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Call(wire.CmdWorldList); err != nil {
			t.Fatal(err)
		}
		return c
	}
	roomKey := func(acct string) []byte {
		var k []byte
		st.DB.QueryRow(ctx, `SELECT key FROM m2_room_keys WHERE account=$1 ORDER BY created DESC LIMIT 1`, acct).Scan(&k)
		return k
	}
	// a request on a fresh connection that names nobody, MAC'd with the member's room key (how the firmware sends the 0x32xx room commands)
	roomCall := func(acct string, cmd uint16, els ...[]byte) *wire.Frame {
		// a fresh connection that names nobody and never pinged: the agent finds the title and login through the room key
		c := &client.Client{Plain: pair(a.ServePlain)}
		k := roomKey(acct)
		f, err := c.CallKey(k, cmd, els...)
		if err != nil {
			t.Fatalf("0x%04x: %v", cmd, err)
		}
		return f
	}
	intAttr := func(id uint16, data []byte) []byte { // request form: [u16 0][8 zero][TLV 0x01 data]
		return wire.TLV(id, 0, append(make([]byte, 10), wire.TLV(1, 2, data)...))
	}
	memberAttr := func(mask []byte) []byte { return wire.TLV(0x59, 0, append(make([]byte, 8), wire.TLV(1, 2, mask)...)) }
	b57, b58, b55, b56 := bytes.Repeat([]byte{0x57}, 128), bytes.Repeat([]byte{0x58}, 128), bytes.Repeat([]byte{0x55}, 92), bytes.Repeat([]byte{0x56}, 92)

	host := login(hostAcct, "PS3Host")
	// CreateJoinRoom step 3: max slot 8, the two internal bins, the host's own 0x59 (one local player)
	cf, err := host.Call(0x3200, wire.TLV(0x3f, 4, []byte{0, 8}), intAttr(0x57, b57), intAttr(0x58, b58), memberAttr([]byte{0, 0, 0, 1}), wire.TLV(0x6e, 2, []byte{10, 0, 0, 1}))
	if err != nil {
		t.Fatal(err)
	}
	if rd := cf.Elements()[0x71]; !bytes.Contains(rd, b57) || !bytes.Contains(rd, b58) {
		t.Fatalf("0x3200 reply does not return the two internal bins")
	}
	if me := cf.Elements()[0x4b]; !bytes.Contains(me, []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01}) && !bytes.Contains(me, wire.TLV(1, 2, []byte{0, 0, 0, 1})) {
		t.Fatalf("0x3200 reply member lacks its 0x59: %x", me)
	}
	roomID := cf.Elements()[0x3a]
	// CreateJoinRoom step 4 (0x1202) sets the external bins and a searchable int; 0x1207 changes the int later
	if _, err := host.Call(0x1202, wire.TLV(0x3a, 2, roomID), wire.TLV(0x55, 2, b55), wire.TLV(0x56, 2, b56), wire.TLV(0x4c, 5, []byte{0, 0, 0, 7})); err != nil {
		t.Fatal(err)
	}
	// DeleteServerContext, JoinRoom/LeaveRoom world steps: empty answers
	for _, cmd := range []uint16{0x1203, 0x1204} {
		if rf, err := host.Call(cmd, wire.TLV(0x3a, 2, roomID)); err != nil || len(rf.Body) != 0 {
			t.Fatalf("0x%04x: %v", cmd, err)
		}
	}

	joiner := login(joinAcct, "PS3Joiner")
	// SearchRoom with an int filter [u32 op EQ=1][TLV 0x4c = 7]
	flt := wire.TLV(0x06, 0, append([]byte{0, 0, 0, 1}, wire.TLV(0x4c, 5, []byte{0, 0, 0, 7})...))
	sf, err := joiner.Call(0x1200, flt)
	if err != nil {
		t.Fatal(err)
	}
	if it := sf.Elements()[0x03]; !bytes.Contains(it, b55) || !bytes.Contains(it, wire.TLV(0x4c, 5, []byte{0, 0, 0, 7})) {
		t.Fatalf("search result lacks the external attrs: %x", it)
	}
	flt = wire.TLV(0x06, 0, append([]byte{0, 0, 0, 1}, wire.TLV(0x4c, 5, []byte{0, 0, 0, 8})...))
	if sf, err = joiner.Call(0x1200, flt); err != nil || bytes.Contains(sf.Elements()[0x03], b55) {
		t.Fatalf("a filter that matches nothing returned the room: %v", err)
	}
	// GetRoomDataExternalList: the room named by its low 16 bits, only attr 0x55 asked for
	lf, err := joiner.Call(0x1208, wire.TLV(0x29, 4, []byte{0, 1}), wire.TLV(0x3d, 4, roomID[6:8]), wire.TLV(0x05, 4, []byte{0, 0x55}))
	if err != nil {
		t.Fatal(err)
	}
	list := lf.Elements()[0x02]
	if len(list) < 4 || binary.BigEndian.Uint16(list[2:]) != 1 || !bytes.Contains(list, b55) || bytes.Contains(list, b56) {
		t.Fatalf("0x1208 list: %x", list)
	}
	// JoinRoom with its 0x59 = 1 local player: the reply carries the internal bins and the host's 0x59 and its own
	time.Sleep(300 * time.Millisecond) // the host's event watch is subscribed
	jf, err := joiner.Call(0x3201, wire.TLV(0x3e, 4, roomID[6:8]), memberAttr([]byte{0, 0, 0, 1}))
	if err != nil {
		t.Fatal(err)
	}
	if rd := jf.Elements()[0x71]; !bytes.Contains(rd, b57) || !bytes.Contains(rd, b58) {
		t.Fatal("0x3201 reply does not return the two internal bins")
	}
	if n := bytes.Count(jf.Elements()[0x02], wire.TLV(1, 2, []byte{0, 0, 0, 1})); n != 2 {
		t.Fatalf("join reply lists %d member 0x59 values, want 2", n)
	}
	// the host hears of the member (0x320c), then of the member's changed 0x59 (0x320d)
	if ef, err := client.ReadFrame(host.Plain); err != nil || ef.Cmd != wire.EventMemberJoined {
		t.Fatalf("expected MemberJoined: %v %+v", err, ef)
	}
	rf := roomCall(joinAcct, 0x3206, wire.TLV(0x16, 4, []byte{0, 0x20}), memberAttr([]byte{0, 0, 0, 3}))
	if rf.Result != 0 {
		t.Fatalf("0x3206 result %d", rf.Result)
	}
	ef, err := client.ReadFrame(host.Plain)
	if err != nil || ef.Cmd != wire.EventMemberUpdated || !ef.Verify(roomKey(hostAcct)) {
		t.Fatalf("expected UpdatedRoomMemberDataInternal: %v %+v", err, ef)
	}
	if !bytes.Equal(ef.Elements()[0x16], []byte{0, 0x20}) || !bytes.Contains(ef.Elements()[0x59], wire.TLV(1, 2, []byte{0, 0, 0, 3})) || binary.BigEndian.Uint16(ef.Raw[14:]) != 0x20 {
		t.Fatalf("member data event: %x", ef.Raw)
	}
	// the host reads the joiner's 0x59 (the call that blocks the game's host flow)
	mf := roomCall(hostAcct, 0x3207, wire.TLV(0x16, 4, []byte{0, 0x20}))
	if me := mf.Elements()[0x4b]; !bytes.Contains(me, wire.TLV(1, 2, []byte{0, 0, 0, 3})) {
		t.Fatalf("0x3207 member: %x", me)
	}
	// the host adds the joiner to its player table (0x3204): stored, answered with 0x70, and pushed to the joiner as 0x320e
	nb := bytes.Repeat([]byte{0x99}, 128)
	pf := roomCall(hostAcct, 0x3204, wire.TLV(0x06, 0, append([]byte{0, 0, 0, 0}, wire.TLV(0x40, 7, make([]byte, 4))...)), intAttr(0x57, nb), intAttr(0x58, b58))
	if len(pf.Elements()[0x70]) != 8 {
		t.Fatalf("0x3204 reply lacks 0x70: %x", pf.Raw)
	}
	var ev *wire.Frame
	for i := 0; i < 5; i++ { // the joiner also receives the update of its own earlier steps; read until the room data event
		if ev, err = client.ReadFrame(joiner.Plain); err != nil || ev.Cmd == wire.EventRoomUpdated {
			break
		}
	}
	if err != nil || ev.Cmd != wire.EventRoomUpdated || !ev.Verify(roomKey(joinAcct)) || !bytes.Contains(ev.Raw, nb) || !bytes.Contains(ev.Raw, b58) {
		t.Fatalf("expected UpdatedRoomDataInternal with the new bins: %v %+v", err, ev)
	}
	// a late joiner's GetRoom shows the stored bins: durable in the core, not in the agent
	if r, err := mm.GetRoom(ctx, mustRoom(t, mm, hostAcct), hostAcct); err != nil || !bytes.Equal(r.Attrs.Bin[wire.AttrInt1], nb) {
		t.Fatalf("core room data: %v", err)
	}
	// the host kicks the joiner
	if kf := roomCall(hostAcct, 0x3211, wire.TLV(0x16, 4, []byte{0, 0x20}), wire.TLV(0x17, 3, []byte{0})); kf.Result != 0 {
		t.Fatalf("0x3211 result %d", kf.Result)
	}
	r, err := mm.GetRoom(ctx, mustRoom(t, mm, hostAcct), hostAcct)
	if err != nil || len(r.Members) != 1 {
		t.Fatalf("joiner still in the room after the kick: %v %+v", err, r)
	}
	mm.LeaveRoom(ctx, mustRoom(t, mm, hostAcct), hostAcct)
}

// mustRoom is the host's room in the core, found through its search.
func mustRoom(t *testing.T, mm *agent.MatchmakingCore, owner string) string {
	t.Helper()
	rs, err := mm.SearchRooms(context.Background(), "mc-e2e", "lce-ps3-0884", []string{"np"}, 20, nil)
	if err == nil {
		for _, r := range rs {
			if r.Owner == owner {
				return r.ID
			}
		}
	}
	t.Fatalf("no room of %s: %v", owner, err)
	return ""
}
