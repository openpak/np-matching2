package agent_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"openpak/np-matching2/agent"
	"openpak/np-matching2/wire"
)

// The room calls against a running matchmaking core (NP_MATCHING_TEST_CORE_ADDR, NP_MATCHING_TEST_CORE_KEY). Skipped without one.
func TestRoomsAgainstCore(t *testing.T) {
	addr := os.Getenv("NP_MATCHING_TEST_CORE_ADDR")
	if addr == "" {
		t.Skip("no core")
	}
	m, conn, err := agent.DialMatchmaking(addr, os.Getenv("NP_MATCHING_TEST_CORE_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx := context.Background()
	const a, b = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	room, err := m.CreateRoom(ctx, "terraria-test", "old-gen-1.2.4", a, 4, []byte("blob"), wire.RoomAttrs{}, nil)
	if err != nil || room.RoomID>>48 != 1 || room.MemberNo != 1 {
		t.Fatalf("create: %v %+v", err, room)
	}
	np := []string{"np"}
	rooms, err := m.SearchRooms(ctx, "terraria-test", "old-gen-1.2.4", np, 20, nil)
	if err != nil || len(rooms) != 1 || rooms[0].Owner != a || rooms[0].Network != "np" || rooms[0].Max != 4 || rooms[0].Members != 1 {
		t.Fatalf("search: %v %+v", err, rooms)
	}
	if other, _ := m.SearchRooms(ctx, "terraria-test", "current-1.4", np, 20, nil); len(other) != 0 {
		t.Fatal("another compat group must not see the room")
	}
	if wiiu, _ := m.SearchRooms(ctx, "terraria-test", "old-gen-1.2.4", []string{"wiiu"}, 20, nil); len(wiiu) != 0 {
		t.Fatal("a search restricted to another network must not see a np room")
	}
	j, err := m.JoinRoom(ctx, room.ID, b, nil)
	if err != nil || j.MemberNo != 2 || len(j.Members) != 2 {
		t.Fatalf("join: %v %+v", err, j)
	}
	if err := m.SetRoomData(ctx, room.ID, a, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := m.LeaveRoom(ctx, room.ID, b); err != nil {
		t.Fatal(err)
	}
	if err := m.LeaveRoom(ctx, room.ID, a); err != nil {
		t.Fatal(err)
	}
	if rooms, _ = m.SearchRooms(ctx, "terraria-test", "old-gen-1.2.4", np, 20, nil); len(rooms) != 0 {
		t.Fatal("an emptied room must be gone")
	}
}

// A Minecraft PS3 room against a running core: the attributes and the member's 0x59 are stored in the core, a searcher sees the external ones
// and can filter on the ints, a joiner gets the internal ones and the host's 0x59, updates and kicks work.
func TestMinecraftRoomAttrsAgainstCore(t *testing.T) {
	addr := os.Getenv("NP_MATCHING_TEST_CORE_ADDR")
	if addr == "" {
		t.Skip("no core")
	}
	m, conn, err := agent.DialMatchmaking(addr, os.Getenv("NP_MATCHING_TEST_CORE_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx := context.Background()
	const host, joiner, other = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333"
	b128, b92 := bytes.Repeat([]byte{0x57}, 128), bytes.Repeat([]byte{0x55}, 92)
	attrs := wire.RoomAttrs{
		Bin: map[uint16][]byte{wire.AttrInt1: b128, wire.AttrInt2: b128, wire.AttrExt1: b92, wire.AttrExt2: b92},
		Int: map[uint16]uint32{0x4c: 7, 0x4d: 1},
	}
	room, err := m.CreateRoom(ctx, "mc-test", "lce-ps3-0884", host, 8, nil, attrs, []byte{0, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	// a non-member sees the compat group's room with its external attrs and ints, never the internal bins
	rooms, err := m.SearchRooms(ctx, "mc-test", "lce-ps3-0884", []string{"np"}, 20, []wire.SearchFilter{{Attr: 0x4c, Op: 1, Value: 7}})
	if err != nil || len(rooms) != 1 {
		t.Fatalf("search eq: %v %+v", err, rooms)
	}
	got := rooms[0].Attrs
	if !bytes.Equal(got.Bin[wire.AttrExt1], b92) || !bytes.Equal(got.Bin[wire.AttrExt2], b92) || got.Int[0x4c] != 7 || got.Int[0x4d] != 1 {
		t.Fatalf("external attrs %+v", got)
	}
	if _, ok := got.Bin[wire.AttrInt1]; ok {
		t.Fatal("a non-member sees an internal bin")
	}
	for op, want := range map[uint32]int{1: 1, 2: 0, 3: 0, 4: 1, 5: 0, 6: 1} {
		r, err := m.SearchRooms(ctx, "mc-test", "lce-ps3-0884", []string{"np"}, 20, []wire.SearchFilter{{Attr: 0x4c, Op: op, Value: 7}})
		if err != nil || len(r) != want {
			t.Fatalf("operator %d: %v %d rooms, want %d", op, err, len(r), want)
		}
	}
	// the joiner gets the internal bins and the host's 0x59 in the join reply, and its own 0x59 is kept
	j, err := m.JoinRoom(ctx, room.ID, joiner, []byte{0, 0, 0, 2})
	if err != nil || !bytes.Equal(j.Attrs.Bin[wire.AttrInt1], b128) || !bytes.Equal(j.Attrs.Bin[wire.AttrInt2], b128) {
		t.Fatalf("join: %v %+v", err, j.Attrs)
	}
	if len(j.Members) != 2 || !bytes.Equal(j.Members[0].Bin, []byte{0, 0, 0, 1}) || !bytes.Equal(j.Members[1].Bin, []byte{0, 0, 0, 2}) {
		t.Fatalf("members %+v", j.Members)
	}
	// the owner rewrites 0x57; a joiner may not
	nb := bytes.Repeat([]byte{9}, 128)
	if err := m.SetRoomAttrs(ctx, room.ID, host, wire.RoomAttrs{Bin: map[uint16][]byte{wire.AttrInt1: nb}}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRoomAttrs(ctx, room.ID, joiner, wire.RoomAttrs{Bin: map[uint16][]byte{wire.AttrInt1: b92}}); err == nil {
		t.Fatal("a joiner changed the owner's room data")
	}
	if err := m.SetMemberBin(ctx, room.ID, joiner, joiner, []byte{0, 0, 0, 3}); err != nil {
		t.Fatal(err)
	}
	r, err := m.GetRoom(ctx, room.ID, host)
	if err != nil || !bytes.Equal(r.Attrs.Bin[wire.AttrInt1], nb) || !bytes.Equal(r.Attrs.Bin[wire.AttrInt2], b128) || !bytes.Equal(r.Members[1].Bin, []byte{0, 0, 0, 3}) {
		t.Fatalf("read back: %v %+v", err, r)
	}
	// a stranger cannot kick; the owner can
	if _, err := m.JoinRoom(ctx, room.ID, other, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.KickMember(ctx, room.ID, joiner, other); err == nil {
		t.Fatal("a joiner kicked a member")
	}
	if err := m.KickMember(ctx, room.ID, host, other); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{joiner, host} {
		m.LeaveRoom(ctx, room.ID, a)
	}
}
