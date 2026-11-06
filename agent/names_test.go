package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"openpak/np-common/coreclient"
	"openpak/np-matching2/wire"
)

// accounts is a fake account core: np links by account, display names by account.
type accounts struct {
	links map[string]string
	names map[string]string
}

func (f accounts) GetAccount(_ context.Context, id string) (*coreclient.Account, error) {
	if n, ok := f.names[id]; ok {
		return &coreclient.Account{ID: id, DisplayName: n}, nil
	}
	return nil, errors.New("no account")
}

func (f accounts) GetLinkByAccount(_ context.Context, id string) (*coreclient.Link, error) {
	if o, ok := f.links[id]; ok {
		return &coreclient.Link{AccountID: id, OnlineID: o}, nil
	}
	return nil, coreclient.ErrNoLink
}

// rooms records what the agent asks the core for and returns a fixed list.
type rooms struct {
	list     []RoomInfo
	networks []string
	joined   int
}

func (r *rooms) CreateRoom(context.Context, string, string, uint32, []byte) (*Room, error) { return nil, nil }
func (r *rooms) LeaveRoom(context.Context, string, string) error                         { return nil }
func (r *rooms) SetRoomData(context.Context, string, string, []byte) error               { return nil }
func (r *rooms) Heartbeat(context.Context, string)                                       {}
func (r *rooms) SearchRooms(_ context.Context, _, _ string, networks []string, _ uint32) ([]RoomInfo, error) {
	r.networks = networks
	var out []RoomInfo
	for _, x := range r.list {
		for _, n := range networks {
			if x.Network == n {
				out = append(out, x)
			}
		}
	}
	return out, nil
}
func (r *rooms) JoinRoom(_ context.Context, session, account string) (*JoinedRoom, error) {
	r.joined++
	return &JoinedRoom{ID: session, MemberNo: 2, Max: 8, Members: []RoomMember{{No: 1, Account: "acc-host"}, {No: 2, Account: account}}}, nil
}

const (
	psHost   = "acc-host"
	wiiuHost = "acc-wiiu"
)

func testAgent(cross ...string) (*Agent, *rooms, *conn) {
	r := &rooms{list: []RoomInfo{
		{ID: "11111111-0000-0000-0000-000000000000", RoomID: 1<<48 | 0x111111110000, Owner: psHost, Network: "np", Max: 8, Members: 1},
		{ID: "22222222-0000-0000-0000-000000000000", RoomID: 1<<48 | 0x222222220000, Owner: wiiuHost, Network: "wiiu", Max: 8, Members: 1},
	}}
	a := &Agent{Rooms: r, CrossNetworks: cross, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Account: accounts{links: map[string]string{psHost: "PS3Test"}, names: map[string]string{wiiuHost: "A Wii U player with a long name"}}}
	st := &conn{stop: make(chan struct{}), sess: &Session{Account: "acc-me", OnlineID: "Joiner", Key: make([]byte, 20)}}
	return a, r, st
}

func frame(cmd uint16, els ...[]byte) *wire.Frame {
	f, _, _ := wire.Parse(wire.Request(make([]byte, 20), cmd, [4]byte{}, els...))
	return f
}

// No room attribute the agent writes may carry an identity (owner rule: names come from the account core, never a row copy).
func TestRoomAttrsCarryNoIdentity(t *testing.T) {
	for _, at := range roomAttrs() {
		n := strings.ToLower(at.GetName())
		for _, bad := range []string{"name", "nick", "online", "npid", "handle", "gamertag", "mii", "email", "country"} {
			if strings.Contains(n, bad) {
				t.Fatalf("room attribute %q looks like identity", at.GetName())
			}
		}
	}
}

func TestOnlineIDIsReadFromTheAccountCore(t *testing.T) {
	a, _, _ := testAgent()
	if got := a.onlineID(context.Background(), psHost); got != "PS3Test" {
		t.Fatalf("np link: %q", got)
	}
	if got := a.onlineID(context.Background(), wiiuHost); got != "A Wii U player w" {
		t.Fatalf("no np link falls back to the core display name cut to 16: %q", got)
	}
	if got := a.onlineID(context.Background(), "unknown"); got != "" {
		t.Fatalf("unknown: %q", got)
	}
}

func TestSearchStaysInNPByDefault(t *testing.T) {
	a, r, st := testAgent()
	out := a.searchRooms(context.Background(), a.log(), Title{}, st, frame(0x1200))
	if out == nil || len(r.networks) != 1 || r.networks[0] != "np" {
		t.Fatalf("networks %v", r.networks)
	}
	if strings.Contains(string(out), "A Wii U") {
		t.Fatal("a Wii U room listed with the flag off")
	}
	if !strings.Contains(string(out), "PS3Test") {
		t.Fatal("owner online id not resolved at read time")
	}
}

func TestCrossNetworkListsButRefusesJoin(t *testing.T) {
	a, r, st := testAgent("wiiu")
	out := a.searchRooms(context.Background(), a.log(), Title{}, st, frame(0x1200))
	if len(r.networks) != 2 || r.networks[1] != "wiiu" || !strings.Contains(string(out), "A Wii U player w") {
		t.Fatalf("cross-network search: %v", r.networks)
	}
	// Join naming the Wii U room by its room id is refused (no relay yet); the PS3 room still joins.
	wiiu := wire.TLV(0x3a, 2, []byte{0, 1, 0x22, 0x22, 0x22, 0x22, 0, 0})
	if a.joinRoom(context.Background(), a.log(), Title{}, st, frame(0x3201, wiiu)) != nil || r.joined != 0 {
		t.Fatal("a cross-network join must be refused until the relay exists")
	}
	ps := wire.TLV(0x3a, 2, []byte{0, 1, 0x11, 0x11, 0x11, 0x11, 0, 0})
	out = a.joinRoom(context.Background(), a.log(), Title{}, st, frame(0x3201, ps))
	if out == nil || r.joined != 1 || !strings.Contains(string(out), "PS3Test") || !strings.Contains(string(out), "Joiner") {
		t.Fatal("np join with names resolved from the core")
	}
}
