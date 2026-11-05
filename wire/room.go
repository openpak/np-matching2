package wire

import "encoding/binary"

// Room reply layouts, decoded from the firmware's parsers (vsh 0x2c3910 reply, 0x2c2c08 room data, 0x2c3580 member). They pass the
// firmware's parser; what a few fields mean is inferred from the API structs and not verified on a console.

// BinAttrEntry is the 0x57/0x58/0x59 shape: [u16 id (not on 0x59)] [8 byte time] TLV 0x01 (data).
func binAttr(id uint16, withID bool, data []byte) []byte {
	var b []byte
	if withID {
		b = binary.BigEndian.AppendUint16(b, id)
	}
	b = append(b, make([]byte, 8)...)
	return append(b, TLV(0x01, 2, data)...)
}

// RoomData is the 0x71 element of a CreateJoinRoom reply (internal variant: every sub-element required).
type RoomData struct {
	ServerID uint16
	WorldID  uint32
	MaxSlot  uint16
	LobbyID  uint64
	RoomID   uint64
	PwMask   uint64
	Flags    []byte // element 0x6d, 0..64 bytes
	Attr1    []byte // element 0x57 data
	Attr2    []byte // element 0x58 data
}

func (r RoomData) Element() []byte {
	b := make([]byte, 0x20, 0x20+160)
	binary.BigEndian.PutUint16(b[0:], r.ServerID)
	binary.BigEndian.PutUint32(b[2:], r.WorldID)
	binary.BigEndian.PutUint16(b[6:], r.MaxSlot)
	binary.BigEndian.PutUint64(b[8:], r.LobbyID)
	binary.BigEndian.PutUint64(b[16:], r.RoomID)
	binary.BigEndian.PutUint64(b[24:], r.PwMask)
	b = append(b, TLV(0x41, 7, make([]byte, 32))...)
	b = append(b, TLV(0x57, 0, binAttr(1, true, r.Attr1))...)
	b = append(b, TLV(0x58, 0, binAttr(2, true, r.Attr2))...)
	b = append(b, TLV(0x6d, 2, r.Flags)...)
	b = append(b, TLV(0x02, 0, []byte{0x00, 0x47, 0, 0})...) // no room groups
	return TLV(0x71, 0, b)
}

// Member is the 0x4b element (internal variant: 0x0b, 0x0c, 0x0d, 0x59, 0x6e all required).
func Member(memberID uint16, onlineID, name string) []byte {
	b := binary.BigEndian.AppendUint16(nil, memberID)
	b = append(b, make([]byte, 8)...) // join date
	b = append(b, 0, 0, 0, 0)         // flag attr
	b = append(b, 0, 0)               // nat type, team id
	nm := make([]byte, 48)
	copy(nm, name)
	b = append(b, TLV(0x0b, 0, NpID(onlineID))...)
	b = append(b, TLV(0x0c, 1, nm)...)
	b = append(b, TLV(0x0d, 1, nil)...)
	b = append(b, TLV(0x59, 0, binAttr(0, false, nil))...)
	b = append(b, TLV(0x6e, 2, nil)...)
	return TLV(0x4b, 0, b)
}

// CreateJoinRoomReply holds the five required elements of the 0x3200 reply.
func CreateJoinRoomReply(roomID uint64, rd RoomData, memberID uint16, onlineID, name string, tok24, tok21 []byte) [][]byte {
	rd.RoomID = roomID
	id := binary.BigEndian.AppendUint64(nil, roomID)
	return [][]byte{TLV(0x24, 2, tok24), TLV(0x3a, 2, id), TLV(0x21, 2, tok21), rd.Element(), Member(memberID, onlineID, name)}
}
