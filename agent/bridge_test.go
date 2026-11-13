package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openpak/np-common/coreclient"
	"openpak/np-common/ticket"
	"openpak/np-matching2/wire"
)

// The attributes of a real Minecraft PS3 01.84 host, from the owner's capture of 2026-11-11 (the 0x1207 request's 0x55 and 0x56, 92 bytes each,
// the 0x3204 request's 0x57 and 0x58, 128 bytes each; a lone host named PS3Test).
const (
	gold55 = "0884000000000000000000000000000000000000505333546573740000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	gold56 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c9d00000000000101001f00000000000000"
	gold57 = "505333546573740000000000000000000080001fa732aa1a0000000300100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	gold58 = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

type fakeBridge struct {
	title, compat, account, game string
	maxSlot                      uint32
	attrs                        wire.RoomAttrs
	bin                          []byte
	ended                        string
	puts                         int
}

func (f *fakeBridge) UpsertBridged(_ context.Context, title, compat, account, game string, maxSlot uint32, attrs wire.RoomAttrs, bin []byte) (*Room, error) {
	f.title, f.compat, f.account, f.game, f.maxSlot, f.attrs, f.bin = title, compat, account, game, maxSlot, attrs, bin
	f.puts++
	return &Room{ID: "bbbbbbbb-0000-0000-0000-000000000000", RoomID: 1<<48 | 0xbbbbbbbb0000, MemberNo: 1}, nil
}
func (f *fakeBridge) EndBridged(_ context.Context, _, game string) error { f.ended = game; return nil }

func bridgeMux(a *Agent) *http.ServeMux {
	mux := http.NewServeMux()
	a.RegisterBridge(mux)
	return mux
}

func bridgeCall(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer bk")
	mux.ServeHTTP(w, r)
	return w
}

// A PUT builds the room a PS3 expects from a real host: the golden session data and player table go into attributes 0x55 to 0x58 exactly as
// the console sets them, the host's 0x59 is one local player, the room is the Minecraft compat group, owned by the host's account (lower
// case), and it needs the bearer key.
func TestBridgePutKeepsTheRoomOfARealHost(t *testing.T) {
	t.Setenv("NP_BRIDGE_KEY", "bk")
	a, _, _ := testAgent()
	a.Titles = map[string]Title{"NPWR05636_00": mcTitle}
	fb := &fakeBridge{}
	a.Bridge = fb
	mux := bridgeMux(a)
	body, _ := json.Marshal(map[string]any{"host_account": "AAAAAAAA-0000-0000-0000-00000000000A", "max_slot": 8, "title": "NPWR05636_00",
		"external": gold55 + gold56, "internal": gold57 + gold58})
	if w := bridgeCall(mux, "PUT", "/internal/bridge/rooms/wiiu:5", string(body)); w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	b := func(h string) []byte { x, _ := hex.DecodeString(h); return x }
	if fb.game != "wiiu:5" || fb.account != "aaaaaaaa-0000-0000-0000-00000000000a" || fb.compat != "lce-ps3-0884" || fb.title != "minecraft" || fb.maxSlot != 8 || !bytes.Equal(fb.bin, []byte{0, 0, 0, 1}) {
		t.Fatalf("core call %+v", fb)
	}
	for id, want := range map[uint16]string{wire.AttrExt1: gold55, wire.AttrExt2: gold56, wire.AttrInt1: gold57, wire.AttrInt2: gold58} {
		if !bytes.Equal(fb.attrs.Bin[id], b(want)) {
			t.Fatalf("attribute 0x%x differs from the real host's", id)
		}
	}
	// refusals: no key, a Wii U net version, a short table
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("PUT", "/internal/bridge/rooms/wiiu:5", strings.NewReader(string(body))))
	if w.Code != 401 {
		t.Fatalf("without a key: %d", w.Code)
	}
	wiiuVer, _ := json.Marshal(map[string]any{"host_account": "aaaaaaaa-0000-0000-0000-00000000000a", "max_slot": 8, "external": "0881" + (gold55 + gold56)[4:], "internal": gold57 + gold58})
	short, _ := json.Marshal(map[string]any{"host_account": "aaaaaaaa-0000-0000-0000-00000000000a", "max_slot": 8, "external": gold55 + gold56, "internal": gold57})
	for name, bad := range map[string]string{"net version": string(wiiuVer), "short table": string(short)} {
		if w := bridgeCall(mux, "PUT", "/internal/bridge/rooms/wiiu:5", bad); w.Code != 400 {
			t.Fatalf("%s: %d", name, w.Code)
		}
	}
	if fb.puts != 1 {
		t.Fatalf("a refused request reached the core: %d", fb.puts)
	}
	if w := bridgeCall(mux, "DELETE", "/internal/bridge/rooms/wiiu:5", ""); w.Code != 200 || fb.ended != "wiiu:5" {
		t.Fatalf("delete: %d ended=%q", w.Code, fb.ended)
	}
}

// The source route lists real hosts' rooms with their session data and leaves bridged rooms out (they are other consoles' games).
func TestBridgeListLeavesBridgedRoomsOut(t *testing.T) {
	t.Setenv("NP_BRIDGE_KEY", "bk")
	a, r, _ := testAgent()
	a.Titles = map[string]Title{"NPWR05636_00": mcTitle}
	b := func(h string) []byte { x, _ := hex.DecodeString(h); return x }
	attrs := wire.RoomAttrs{Bin: map[uint16][]byte{wire.AttrExt1: b(gold55), wire.AttrExt2: b(gold56)}}
	r.list = []RoomInfo{
		{ID: "real", RoomID: 1, Owner: psHost, Network: "np", Max: 8, Attrs: attrs},
		{ID: "bridged", RoomID: 2, Owner: wiiuHost, Network: "np", Max: 8, Attrs: attrs, Bridge: "wiiu:5"},
		{ID: "terraria-like", RoomID: 3, Owner: psHost, Network: "np", Max: 8}, // no Minecraft session data
	}
	w := bridgeCall(bridgeMux(a), "GET", "/internal/bridge/rooms", "")
	var got []bridgedRoomOut
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got) != 1 || got[0].ID != "real" || got[0].Owner != psHost || got[0].External != gold55+gold56 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
}

// A PS3 that joins a bridged room gets the normal JoinRoom reply (the host as owner, itself as member) and its join is logged in full and
// handed to the directory with its member data, the request and who it is.
func TestJoinOfABridgedRoomIsReported(t *testing.T) {
	t.Setenv("NP_BRIDGE_KEY", "bk")
	a, r, st := testAgent()
	r.list = []RoomInfo{{ID: "bridged-room", RoomID: 1<<48 | 0x333333330000, Owner: psHost, Network: "np", Max: 8, Bridge: "wiiu:5"}}
	out := a.joinRoom(context.Background(), a.log(), mcTitle, st, frame(0x3201, wire.TLV(0x3a, 2, []byte{0, 1, 0x33, 0x33, 0x33, 0x33, 0, 0}), reqMember([]byte{0, 0, 0, 1})))
	f := reply(t, out)
	if f.Result != 0 || !strings.Contains(string(out), "PS3Test") || !strings.Contains(string(out), "Joiner") {
		t.Fatalf("join reply result=%d", f.Result)
	}
	w := bridgeCall(bridgeMux(a), "GET", "/internal/bridge/joins?after=0", "")
	var js []joinEvent
	if err := json.Unmarshal(w.Body.Bytes(), &js); err != nil || len(js) != 1 {
		t.Fatalf("joins: %s", w.Body)
	}
	j := js[0]
	if j.Game != "wiiu:5" || j.Kind != "join" || j.Native != "Joiner" || j.Account != "acc-me" || j.Data["member_bin"] != "00000001" || j.Data["host"] != psHost || j.Data["request"] == "" {
		t.Fatalf("join event %+v", j)
	}
	if w := bridgeCall(bridgeMux(a), "GET", "/internal/bridge/joins?after=1", ""); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("cursor: %s", w.Body)
	}
	// a join of a real room is not reported
	r.list = []RoomInfo{{ID: "real", RoomID: 1<<48 | 0x333333330000, Owner: psHost, Network: "np", Max: 8}}
	a.joinRoom(context.Background(), a.log(), mcTitle, st, frame(0x3201, wire.TLV(0x3a, 2, []byte{0, 1, 0x33, 0x33, 0x33, 0x33, 0, 0})))
	if n := len(a.joins.after(0)); n != 1 {
		t.Fatalf("a real room's join was reported: %d events", n)
	}
}

// The bridge's PS3 joiner leg asks who a player is on the PS3 network: online id, country, NP domain, and with ticket=1 a ticket that verifies
// as that player and the Minecraft title's passphrase. Without the bearer key, or for an account without an np link, nothing is issued.
func TestBridgeIdentity(t *testing.T) {
	t.Setenv("NP_BRIDGE_KEY", "bk")
	a, _, _ := testAgent()
	const psHost = "aaaaaaaa-0000-0000-0000-0000000000a1"
	a.Account = withLinkID{accounts{links: map[string]string{psHost: "PS3Test"}, names: map[string]string{psHost: "PS3 host"}, countries: map[string]string{psHost: "PT"}}}
	pass := make([]byte, 128)
	pass[0] = 0xab
	a.Titles = map[string]Title{"NPWR05636_00": {Key: "minecraft", Compat: "lce-ps3-0884", Status: 1, Pass: pass}}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a.Tickets, _ = ticket.New(priv, nil)
	mux := bridgeMux(a)

	w := bridgeCall(mux, "GET", "/internal/bridge/identity?account="+psHost, "")
	var out identityOut
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.OnlineID != "PS3Test" || out.Country != "pt" || out.Domain != "pt.pt.np.playstation.net" || out.Ticket != "" || out.Passphrase != "" {
		t.Fatalf("identity: %d %s", w.Code, w.Body)
	}
	w = bridgeCall(mux, "GET", "/internal/bridge/identity?ticket=1&account="+psHost, "")
	out = identityOut{}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Comm != "NPWR05636_00" || !strings.HasPrefix(out.Passphrase, "ab00") || len(out.Passphrase) != 256 {
		t.Fatalf("identity with ticket: %d %s", w.Code, w.Body)
	}
	raw, err := base64.StdEncoding.DecodeString(out.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.Tickets.Verify(raw)
	if err != nil || id.AccountID != psHost || id.OnlineID != "PS3Test" || id.Country != "pt" {
		t.Fatalf("ticket: %+v %v", id, err)
	}
	if w := bridgeCall(mux, "GET", "/internal/bridge/identity?account=11111111-2222-3333-4444-555555555555", ""); w.Code != 404 {
		t.Fatalf("an account with no np link: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "/internal/bridge/identity?account="+psHost, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != 401 {
		t.Fatalf("no bearer key: %d", rec.Code)
	}
}

// withLinkID gives the fake core's links an id, which a ticket needs.
type withLinkID struct{ accounts }

func (f withLinkID) GetLinkByAccount(ctx context.Context, id string) (*coreclient.Link, error) {
	l, err := f.accounts.GetLinkByAccount(ctx, id)
	if l != nil {
		l.LinkID = "link-1"
	}
	return l, err
}
