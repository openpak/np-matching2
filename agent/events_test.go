package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"openpak/np-matching2/wire"
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

// The experiment's variants: baseline first on the room connection, then the other connections of the host (latest room request first),
// then the two element variants; every one verifies with the room key and keeps the member at +14.
func TestExperimentVariants(t *testing.T) {
	key := []byte("room-key-16bytes")
	room := &conn{id: 1}
	older, newer, joiner := &conn{id: 2}, &conn{id: 3}, &conn{id: 4}
	older.lastRoom.Store(20)
	newer.lastRoom.Store(10)
	a := &Agent{allConns: map[*conn]string{room: "host", older: "host", newer: "host", joiner: "joiner"}}
	vs := a.expVariants(room, "host", "0123456789abcdef", key, wire.MemberInfo{No: 3, Name: "SwitchTest", Country: "gb", Addr: []byte{1, 2, 3, 4}})
	var got []string
	for _, v := range vs {
		f, _, err := wire.Parse(v.pkt)
		if err != nil || !f.Verify(key) || f.Cmd != wire.EventMemberJoined || binary.BigEndian.Uint16(v.pkt[14:]) != 0x30 || len(f.Elements()[0x4b]) == 0 {
			t.Fatalf("%s: %v %x", v.name, err, v.pkt)
		}
		got = append(got, fmt.Sprintf("%s@%d", v.name, v.c.id))
	}
	if want := "[baseline@1 other-conn@2 other-conn@3 bare-member@1 with-0x3a-room-id@1]"; fmt.Sprint(got) != want {
		t.Fatalf("order %v, want %s", got, want)
	}
	if m := mustEl(vs[3].pkt, 0x4b); bytes.Contains(m, []byte{0x20, 0x6e}) || bytes.Contains(m, []byte{0x00, 0x59}) {
		t.Fatalf("bare member still has 0x59/0x6e: %x", m)
	}
	if r := mustEl(vs[4].pkt, 0x3a); len(r) != 8 || binary.BigEndian.Uint64(r) != roomIDOf("0123456789abcdef") {
		t.Fatalf("0x3a %x", r)
	}
}

func mustEl(pkt []byte, id uint16) []byte {
	f, _, _ := wire.Parse(pkt)
	return f.Elements()[id]
}
