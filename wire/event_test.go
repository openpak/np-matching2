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

// TestEventHeader pins the kind-4 header the firmware dispatches on (vsh 0x2b4db4): room handle at +12 = room data head[0..2], new member
// id at +14 in slot form (id>>4 = slot), and the member element's own id in the same form.
func TestEventHeader(t *testing.T) {
	key := []byte("room-key-16bytes")
	pkt := Event(key, EventMemberJoined, MemberID(3), MemberOf(MemberInfo{No: 3, Name: "Joiner", Addr: []byte{1, 2, 3, 4}, NAT: 2}))
	f, rest, err := Parse(pkt)
	if err != nil || len(rest) != 0 || f.Kind != KindEvent || f.Cmd != EventMemberJoined || !f.Verify(key) {
		t.Fatalf("%v %+v", err, f)
	}
	want := []byte{0x11, 0x04, byte(len(pkt) >> 8), byte(len(pkt)), 0x32, 0x0c, 0, 0, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x30}
	if !bytes.Equal(pkt[:16], want) {
		t.Fatalf("header %x, want %x", pkt[:16], want)
	}
	rd := RoomData{WorldID: 1, MaxSlot: 8}.Element()[4:] // past the TLV head
	if binary.BigEndian.Uint16(rd) != binary.BigEndian.Uint16(pkt[12:]) || !bytes.Equal(rd[8:24], make([]byte, 16)) {
		t.Fatalf("room data head %x does not carry the event room handle / a zero slot map", rd[:32])
	}
	m := f.Elements()[0x4b]
	if binary.BigEndian.Uint16(m) != 0x30 || m[14] != 2 || !bytes.Contains(m, []byte{0x20, 0x6e, 0, 4, 1, 2, 3, 4}) {
		t.Fatalf("member %x", m)
	}
}
