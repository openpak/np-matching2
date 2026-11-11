package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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
// id at +14 in slot form (MemberID), and the member element's own id the same.
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

// TestRoomEventsGolden pins the room events byte for byte and replays what the firmware does with them (research matching2-protocol §37):
// the room key is the AES-128-ECB decryption of the 0x24 token with the session key (vsh 0x29cb6c -> 0x2903a8; the 0x21 token is only copied),
// the event MAC verifies with it (0x2b4bd8), +12 equals the room data head the create reply gave (room+10, 0x29bae0), +14 is the subject in
// slot form (0x29ef9c), never slot 0 (the owner alias, 0x29ec18). Changing these bytes must be deliberate.
func TestRoomEventsGolden(t *testing.T) {
	sess := []byte("session-key-16by-xyz")
	roomKey := []byte("room-key-16bytes")
	tok, err := RoomKeyToken(sess, roomKey)
	if err != nil {
		t.Fatal(err)
	}
	create := Reply(sess, 0x3200, 0, [4]byte{0, 0, 0, 7}, CreateJoinRoomReply(0x0001aaaabbbbcccc, RoomData{WorldID: 1, MaxSlot: 8},
		MemberInfo{No: 1, Name: "PS3Test", Country: "pt", NAT: 2, Owner: true}, tok, tok)...)
	cf, _, _ := Parse(create)
	k, err := RoomKeyFromToken(sess, cf.Elements()[0x24]) // what the console stores at room+0x3f8
	if err != nil || !bytes.Equal(k, roomKey) {
		t.Fatalf("console room key %x %v", k, err)
	}
	head := binary.BigEndian.Uint16(cf.Elements()[0x71])

	joined := Event(roomKey, EventMemberJoined, MemberID(3), MemberOf(MemberInfo{No: 3, Name: "SwitchTest", Country: "gb", Addr: []byte{10, 87, 0, 2}, NAT: 1}))
	left := MemberLeft(roomKey, MemberID(3), NpID("SwitchTest", "gb"), CauseLeave)
	gone := RoomDestroyed(roomKey, CauseLeave)
	for _, c := range []struct {
		name    string
		pkt     []byte
		subject uint16
		want    string
	}{
		{"0x320c", joined, 0x30, "110400a0320c00000000000000010030d5967ca4ef7133c1fea658ae55e7b541004b007c00300000000000000000000000000100000b0018537769746368546573740000000000006762676270733300100c0030537769746368546573740000000000000000000000000000000000000000000000000000000000000000000000000000100d00000059000c000000000000000020010000206e00040a570002"},
		{"0x320f", left, 0x30, "11040047320f00000000000000010030eefc05e210ac642c8db680ead10d4e2e401600020030000b00185377697463685465737400000000000067626762707333003062000101"},
		{"0x3213", gone, 0, "110400253213000000000000000100002525f5daaa5cff0bc75c284ad6f647a23062000101"},
	} {
		f, rest, err := Parse(c.pkt)
		if err != nil || len(rest) != 0 || f.Kind != KindEvent || !f.Verify(k) {
			t.Fatalf("%s: does not verify with the console's room key: %v", c.name, err)
		}
		if binary.BigEndian.Uint16(c.pkt[12:]) != head || binary.BigEndian.Uint16(c.pkt[14:]) != c.subject || !bytes.Equal(c.pkt[6:12], make([]byte, 6)) {
			t.Fatalf("%s: header %x", c.name, c.pkt[:16])
		}
		if c.want != "" && hex.EncodeToString(c.pkt) != c.want {
			t.Errorf("%s changed:\n got %x\nwant %s", c.name, c.pkt, c.want)
		}
	}
	m := mustElems(t, joined)[0x4b]
	if id := binary.BigEndian.Uint16(m); id != 0x30 || id>>4 == 0 || binary.BigEndian.Uint32(m[10:]) != 0 {
		t.Fatalf("joined member %x: id must equal +14, not slot 0, no owner flag", m[:14])
	}
	el := mustElems(t, left)
	if binary.BigEndian.Uint16(el[0x16]) != 0x30 || len(el[0x0b]) != 24 || !bytes.Equal(el[0x62], []byte{CauseLeave}) {
		t.Fatalf("left elements %x", left[32:])
	}
}

func mustElems(t *testing.T, pkt []byte) map[uint16][]byte {
	f, _, err := Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return f.Elements()
}
