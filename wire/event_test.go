package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRoomKeyTokenRoundTrip(t *testing.T) {
	sess := bytes.Repeat([]byte{7}, 20)
	room := []byte("0123456789abcdef")
	tok, err := RoomKeyToken(sess, room)
	if err != nil || bytes.Equal(tok, room) || len(tok) != 16 {
		t.Fatalf("token %x %v", tok, err)
	}
	if k, err := RoomKeyFromToken(sess, tok); err != nil || !bytes.Equal(k, room) {
		t.Fatalf("decrypt %x %v", k, err)
	}
	if _, err := RoomKeyToken(sess, []byte("short")); err == nil {
		t.Fatal("a room key that is not a 16-byte multiple must fail")
	}
}

func TestEventHeader(t *testing.T) {
	key := []byte("room-key-16bytes")
	pkt := Event(key, EventMemberJoined, 0x0001aaaabbbbcccc, MemberOf(MemberInfo{No: 2, Name: "Joiner", Addr: []byte{1, 2, 3, 4}, NAT: 2}))
	f, rest, err := Parse(pkt)
	if err != nil || len(rest) != 0 || f.Kind != KindEvent || f.Cmd != EventMemberJoined || !f.Verify(key) {
		t.Fatalf("%v %+v", err, f)
	}
	if binary.BigEndian.Uint64(pkt[8:16]) != 0x0001aaaabbbbcccc || pkt[0] != 0x11 {
		t.Fatalf("header %x", pkt[:16])
	}
	m := f.Elements()[0x4b]
	if binary.BigEndian.Uint16(m) != 2 || m[14] != 2 || !bytes.Contains(m, []byte{0x20, 0x6e, 0, 4, 1, 2, 3, 4}) {
		t.Fatalf("member %x", m)
	}
}
