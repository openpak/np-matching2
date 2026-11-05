package agent_test

import (
	"context"
	"os"
	"testing"

	"openpak/np-matching2/agent"
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
	room, err := m.CreateRoom(ctx, "terraria-test", a, "Host", 4, []byte("blob"))
	if err != nil || room.RoomID>>48 != 1 || room.MemberNo != 1 {
		t.Fatalf("create: %v %+v", err, room)
	}
	rooms, err := m.SearchRooms(ctx, "terraria-test", "old-gen-1.2.4", 20)
	if err != nil || len(rooms) != 1 || rooms[0].Owner != "Host" || rooms[0].Max != 4 || rooms[0].Members != 1 {
		t.Fatalf("search: %v %+v", err, rooms)
	}
	if other, _ := m.SearchRooms(ctx, "terraria-test", "current-1.4", 20); len(other) != 0 {
		t.Fatal("another compat group must not see the room")
	}
	j, err := m.JoinRoom(ctx, room.ID, b, "Guest")
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
	if rooms, _ = m.SearchRooms(ctx, "terraria-test", "old-gen-1.2.4", 20); len(rooms) != 0 {
		t.Fatal("an emptied room must be gone")
	}
}
