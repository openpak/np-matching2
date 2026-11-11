package agent

import (
	"context"
	"testing"
)

// Only the connection that created or joined the room sends its events (conn.pushRoom, vsh 0x29ba04). A second connection of the same account
// (the console's main agent connection) sends nothing: it returns before any store or core lookup, so the nil Store here would panic otherwise.
func TestRoomEventsOnlyOnTheRoomConnection(t *testing.T) {
	a := &Agent{}
	main, room := &conn{}, &conn{}
	room.setPushRoom("s1")
	for _, typ := range []string{"member_joined", "member_left", "session_ended", "session_updated", "member_updated"} {
		a.pushEvent(context.Background(), main, "host", "PS3Test", RoomEvent{Type: typ, Session: "s1", Subject: "joiner", MemberNo: 3})
	}
	if main.carries("s1") || !room.carries("s1") || room.carries("s2") || room.carries("") {
		t.Fatal("carries")
	}
	if causeOf("leave") != 1 || causeOf("kicked") != 2 || causeOf("expired") != 5 {
		t.Fatal("causes")
	}
}
