package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"openpak/np-matching2/wire"
)

// The PS3 joiner's path through a bridged room (card openpak/prds#177, 2026-11-13 16:02Z: the owner's real PS3 selected a Wii U-hosted game
// and stopped after GetRoomDataExternalList). The golden request is the game's own, as np-matching2 logged it: server 0xced4 and room part
// 0xc58c (the two u16 the firmware derives from the room id the presence blob carries), and six attribute ids: the game's 0x55 and 0x56
// with the type nibble (0x2055, 0x2056) and the four the firmware adds for the owner info (0x000b NpId, 0x100c name, 0x100d avatar, 0x206c
// the host's external info).

const bridgedRoomID = uint64(1)<<48 | 0xced40a83c58c

// bridgedRoom is a room the directory advertises for a Wii U host: the golden session data with the joinable byte set the way the
// directory sets it (+0xaf = 1 as a real host does ~6 s after creating the room), the golden table, the star signalling option.
func bridgedRoom() RoomInfo {
	b := func(h string) []byte { x, _ := hex.DecodeString(h); return x }
	ext := append(b(gold55), b(gold56)...)
	ext[0xad], ext[0xaf] = 1, 1
	return RoomInfo{ID: "ced40a83-c58c-4edf-82a7-3d5c75f7c83a", RoomID: bridgedRoomID, Owner: wiiuHost, Network: "np", Max: 8, Members: 1, Bridge: "wiiu:13",
		Attrs: bridgedAttrs(ext, append(b(gold57), b(gold58)...))}
}

func bridgeAgent() (*Agent, *rooms, *conn) {
	a, r, st := testAgent()
	r.list = []RoomInfo{bridgedRoom()}
	a.Account = accounts{links: map[string]string{psHost: "PS3Test", "acc-me": "Joiner", wiiuHost: "WiiUTest"},
		names: map[string]string{wiiuHost: "WiiUTest"}, countries: map[string]string{psHost: "PT", "acc-me": "us", wiiuHost: "GB"}}
	return a, r, st
}

type tlvItem struct {
	typ, id uint16
	val     []byte
}

func walkTLVs(b []byte) []tlvItem {
	var out []tlvItem
	for len(b) >= 4 {
		h := binary.BigEndian.Uint16(b)
		n := int(binary.BigEndian.Uint16(b[2:]))
		if 4+n > len(b) {
			break
		}
		out = append(out, tlvItem{h >> 12, h & 0xfff, b[4 : 4+n]})
		b = b[4+n:]
	}
	return out
}

// The checks the game makes on the list reply (EB 0xc96560 event 5, 0xc896a0, list build 0xc87b04), run against what the room server returns.
func TestExternalListForTheGamesOwnRequest(t *testing.T) {
	a, _, st := bridgeAgent()
	req := frame(0x1208, wire.TLV(0x29, 4, []byte{0xce, 0xd4}), wire.TLV(0x3d, 4, []byte{0xc5, 0x8c}),
		wire.TLV(0x05, 4, []byte{0x10, 0x0c}), wire.TLV(0x05, 4, []byte{0x10, 0x0d}), wire.TLV(0x05, 4, []byte{0x00, 0x0b}),
		wire.TLV(0x05, 4, []byte{0x20, 0x6c}), wire.TLV(0x05, 4, []byte{0x20, 0x55}), wire.TLV(0x05, 4, []byte{0x20, 0x56}))
	f := reply(t, a.roomDataExternalList(context.Background(), a.log(), mcTitle, st, req))
	list := f.Elements()[0x02]
	if len(list) < 4 || binary.BigEndian.Uint16(list) != 0x45 || binary.BigEndian.Uint16(list[2:]) != 1 {
		t.Fatalf("the game needs exactly one room in the list: %x", list)
	}
	items := walkTLVs(list[4:])
	if len(items) != 1 || items[0].id != 0x45 {
		t.Fatalf("items %+v", items)
	}
	item := items[0].val
	head := item[:0x24] // room id parts, flag attr, max slot, owner NpId
	if binary.BigEndian.Uint16(head) != 0xced4 || binary.BigEndian.Uint16(head[2:]) != 0x0a83 || binary.BigEndian.Uint16(head[4:]) != 0xc58c {
		t.Fatalf("room id parts % x", head[:6])
	}
	var bins [][]byte
	got := map[uint16]bool{}
	for _, e := range walkTLVs(item[0x24:]) {
		got[e.id] = true
		if e.id == 0x54 || e.id == 0x55 || e.id == 0x56 {
			bins = append(bins, e.val) // the firmware's item parser files these into the external bin attr array in order
		}
	}
	if len(bins) != 2 || len(bins[0]) != 92 || len(bins[1]) != 92 {
		t.Fatalf("the game needs exactly two external bin attrs of 0x5c bytes, got %d", len(bins))
	}
	for _, id := range []uint16{0x0b, 0x0c, 0x0d, 0x41} {
		if !got[id] {
			t.Fatalf("item lacks element 0x%x: %x", id, item)
		}
	}
	// list build: net version, +0xad (joinable), +0xaf (loaded) of the session data the two attrs make up
	s := append(append([]byte{}, bins[0]...), bins[1]...)
	if binary.BigEndian.Uint16(s) != 0x0884 || s[0xad] == 0 || s[0xaf] == 0 {
		t.Fatalf("the game's list drops this room: version %x +0xad %d +0xaf %d", s[:2], s[0xad], s[0xaf])
	}
	// the owner info the firmware asked for is the host's own NpId: online id + the realm options np-community's JID uses
	for _, e := range walkTLVs(item[0x24:]) {
		if e.id == 0x0b && string(bytes.TrimRight(e.val[:16], "\x00")) != "WiiUTest" || e.id == 0x0b && string(e.val[16:]) != "gbgbps3\x00" {
			t.Fatalf("owner NpId %x", e.val)
		}
	}
	// the request as the probe sends it (plain ids) still works
	req = frame(0x1208, wire.TLV(0x29, 4, []byte{0, 1}), wire.TLV(0x3d, 4, []byte{0xc5, 0x8c}), wire.TLV(0x05, 4, []byte{0, 0x55}), wire.TLV(0x05, 4, []byte{0, 0x56}))
	f = reply(t, a.roomDataExternalList(context.Background(), a.log(), mcTitle, st, req))
	if l := f.Elements()[0x02]; bytes.Count(l, wire.TLV(0x55, 2, bins[0])) != 1 || bytes.Count(l, wire.TLV(0x56, 2, bins[1])) != 1 || bytes.Contains(l, wire.TLV(0x0b, 0, nil)[:2]) {
		t.Fatalf("plain ids: %x", l)
	}
	if got := hex.EncodeToString(item); got != goldBridgedListItem {
		t.Fatalf("list item changed:\n got %s\nwant %s", got, goldBridgedListItem)
	}
}

// A real host's 0x1202 sets its external info (0x6c); a joiner that asks for it gets it back as the host wrote it.
func TestExternalInfoOfARealHostIsEchoed(t *testing.T) {
	a, r, st := testAgent()
	info, _ := hex.DecodeString("25e4cd7d000000000a570007")
	b55, b56 := bytes.Repeat([]byte{0x55}, 92), bytes.Repeat([]byte{0x56}, 92)
	st.room = "r"
	reply(t, a.setExternal(context.Background(), a.log(), st, frame(0x1202, wire.TLV(0x3a, 2, make([]byte, 8)), wire.TLV(0x55, 2, b55), wire.TLV(0x56, 2, b56), wire.TLV(0x6c, 2, info))))
	if len(r.setAttrs) != 1 || !bytes.Equal(r.setAttrs[0].Bin[wire.AttrExtra], info) {
		t.Fatalf("0x6c not kept: %+v", r.setAttrs)
	}
	r.list[0].Attrs = r.setAttrs[0]
	req := frame(0x1208, wire.TLV(0x29, 4, []byte{0, 1}), wire.TLV(0x3d, 4, []byte{0x11, 0x11}), wire.TLV(0x05, 4, []byte{0x20, 0x6c}), wire.TLV(0x05, 4, []byte{0x20, 0x55}), wire.TLV(0x05, 4, []byte{0x20, 0x56}))
	if l := reply(t, a.roomDataExternalList(context.Background(), a.log(), mcTitle, st, req)).Elements()[0x02]; !bytes.Contains(l, wire.TLV(0x6c, 2, info)) {
		t.Fatalf("0x6c not echoed: %x", l)
	}
}

// bridgedRooms is the fake core for the join: it hands back the bridged room's attributes and the host as owner.
type bridgedRooms struct{ *rooms }

func (b bridgedRooms) JoinRoom(_ context.Context, session, account string, bin []byte) (*JoinedRoom, error) {
	b.rooms.joined++
	r := bridgedRoom()
	return &JoinedRoom{ID: session, RoomID: r.RoomID, MemberNo: 2, Max: 8, Attrs: r.Attrs,
		Members: []RoomMember{{No: 1, Account: wiiuHost, Owner: true, Bin: bridgedMemberBin}, {No: 2, Account: account, Bin: bin}}}, nil
}

// The reply to the JoinRoom the PS3 sends after GetServerInfo and CreateServerContext: what the game reads at event 0x102 (EB 0xc96560): its
// member id, the room id, the host's table (0x57, 0x58), the star signalling option, the host flagged as owner with an NpId that signals to
// the host's JID, and itself.
func TestJoinReplyOfABridgedRoom(t *testing.T) {
	t.Setenv("NP_BRIDGE_KEY", "bk")
	a, r, st := bridgeAgent()
	a.Rooms = bridgedRooms{r}
	out := a.joinRoom(context.Background(), a.log(), mcTitle, st, frame(0x3201, wire.TLV(0x29, 4, []byte{0xce, 0xd4}), wire.TLV(0x3e, 4, []byte{0xc5, 0x8c}), reqMember([]byte{0, 0, 0, 1})))
	f := reply(t, out)
	if f.Result != 0 {
		t.Fatalf("result %d", f.Result)
	}
	el := f.Elements()
	if !bytes.Equal(el[0x16], []byte{0x00, 0x20}) || !bytes.Equal(el[0x3a], binary.BigEndian.AppendUint64(nil, bridgedRoomID)) {
		t.Fatalf("member id %x room id %x", el[0x16], el[0x3a])
	}
	rd := el[0x71]
	for _, want := range [][]byte{wire.TLV(0x6d, 2, []byte{2, 0, 0, 0, 0, 0, 0, 0})} {
		if !bytes.Contains(rd, want) {
			t.Fatalf("room data lacks %x: %x", want, rd)
		}
	}
	var seen []uint16
	for _, e := range walkTLVs(rd[0x20:]) {
		seen = append(seen, e.id)
		if e.id == 0x57 || e.id == 0x58 {
			table, _ := hex.DecodeString(map[uint16]string{0x57: gold57, 0x58: gold58}[e.id])
			if !bytes.HasSuffix(e.val, table) || e.val[0] != 0 || e.val[1] != 0x10 {
				t.Fatalf("internal attr 0x%x: last writer or table wrong: %x", e.id, e.val[:16])
			}
		}
	}
	if fmt.Sprint(seen) != "[65 87 88 109 2]" {
		t.Fatalf("room data elements %v", seen)
	}
	list := el[0x02]
	if binary.BigEndian.Uint16(list[2:]) != 2 {
		t.Fatalf("members %x", list)
	}
	members := walkTLVs(list[4:])
	owner, me := members[0].val, members[1].val
	if binary.BigEndian.Uint16(owner) != 0x10 || binary.BigEndian.Uint32(owner[10:]) != wire.OwnerFlag {
		t.Fatalf("the host is not flagged owner: %x", owner[:16])
	}
	if binary.BigEndian.Uint32(me[10:]) != 0 || binary.BigEndian.Uint16(me) != 0x20 {
		t.Fatalf("joiner entry %x", me[:16])
	}
	var npid, bin59 []byte
	for _, e := range walkTLVs(owner[16:]) {
		switch e.id {
		case 0x0b:
			npid = e.val
		case 0x59:
			bin59 = e.val
		}
	}
	// the NpId a PS3 signals toward: online id + <cc><cc>ps3, the realm np-community's JID for the host's account uses (gb.gb.np.playstation.net)
	if string(bytes.TrimRight(npid[:16], "\x00")) != "WiiUTest" || string(npid[16:]) != "gbgbps3\x00" {
		t.Fatalf("owner NpId % x", npid)
	}
	if !bytes.HasSuffix(bin59, []byte{0, 0, 0, 1}) {
		t.Fatalf("owner 0x59 %x", bin59)
	}
	if got := hex.EncodeToString(owner); got != goldBridgedOwnerMember {
		t.Fatalf("owner member changed:\n got %s\nwant %s", got, goldBridgedOwnerMember)
	}
	// and the join reaches the directory with the member data
	if js := a.joins.after(0); len(js) != 1 || js[0].Game != "wiiu:13" || js[0].Data["member_bin"] != "00000001" {
		t.Fatalf("join feed %+v", js)
	}
}

const (
	goldBridgedListItem    = "ced40a83c58c0000000000085769695554657374000000000000000067626762707333007041002000000000000000000000000000000000000000000000000000000000000000002055005c08840000000000000000000000000000000000005053335465737400000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002056005c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c9d00000000000101011f00000000000000000b0018576969555465737400000000000000006762676270733300100c0030576969555465737400000000000000000000000000000000000000000000000000000000000000000000000000000000100d0000"
	goldBridgedOwnerMember = "00100000000000000000800000000000000b0018576969555465737400000000000000006762676270733300100c0030576969555465737400000000000000000000000000000000000000000000000000000000000000000000000000000000100d00000059001000000000000000002001000400000001206e0000"
)
