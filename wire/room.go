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

// ServerID is head[0..2] of every room data element. The firmware stores it at room+10 and finds the room of a kind-4 event by it (Event).
const ServerID = 1

// RoomData is the 0x71 element of a CreateJoinRoom reply (internal variant: every sub-element required). Head as the firmware parses it
// (vsh 0x2c2c0c, stored by 0x29cb6c): u16 -> room+10 (the event room handle), u32 -> room+0x10, u16 -> room+0xc (max slot), 16 bytes ->
// room+0x1b0 (2 bits per slot, written per member by vsh 0x290128: zero), u64 -> room+0x1c0 (password slot mask).
type RoomData struct {
	WorldID uint32
	RoomID  uint64 // head[16..24]. v0.2.17 zeroed it and a real PS3 froze in Terraria right after 0x3200 (2026-11-10 21:05Z)
	MaxSlot uint16
	PwMask  uint64
	Flags   []byte // element 0x6d, 0..64 bytes
	Attr1   []byte // element 0x57 data
	Attr2   []byte // element 0x58 data
	// LastMember is the wire id of the member that last wrote the internal attrs. Zero keeps the ids 1 and 2 Terraria was verified with.
	LastMember uint16
}

func (r RoomData) Element() []byte {
	b := make([]byte, 0x20, 0x20+160)
	binary.BigEndian.PutUint16(b[0:], ServerID)
	binary.BigEndian.PutUint32(b[2:], r.WorldID)
	binary.BigEndian.PutUint16(b[6:], r.MaxSlot)
	binary.BigEndian.PutUint64(b[16:], r.RoomID)
	binary.BigEndian.PutUint64(b[24:], r.PwMask)
	b = append(b, TLV(0x41, 7, make([]byte, 32))...)
	l1, l2 := uint16(1), uint16(2)
	if r.LastMember != 0 {
		l1, l2 = r.LastMember, r.LastMember
	}
	b = append(b, internalAttr(AttrInt1, l1, r.Attr1)...)
	b = append(b, internalAttr(AttrInt2, l2, r.Attr2)...)
	b = append(b, TLV(0x6d, 2, r.Flags)...)
	b = append(b, TLV(0x02, 0, []byte{0x00, 0x47, 0, 0})...) // no room groups
	return TLV(0x71, 0, b)
}

// Member is the 0x4b element (internal variant: 0x0b, 0x0c, 0x0d, 0x59, 0x6e all required).
func Member(memberID uint16, onlineID, name string) []byte {
	return MemberOf(MemberInfo{No: uint32(memberID), Name: onlineID, Nick: name})
}

// OwnerFlag is the member flag attr bit of the room owner (SCE_NP_MATCHING2_ROOMMEMBER_FLAG_ATTR_OWNER). The firmware sets the room's owner
// pointer from it (vsh 0x29f374 -> 0x29ec18 4th arg = flag>>31) and hands it to the game as memberList.owner (vsh 0x29e864: owner = the
// member whose flag attr is negative). Terraria dereferences memberList.owner with no NULL check right after a successful CreateJoinRoom
// (EBOOT 0x126bc0 lwz r9,12(r24); 0x126be4 lhz r0,56(r9)): without this bit it reads address 0x38 and the game freezes.
const OwnerFlag = 0x80000000

// MemberOf encodes a member with its NAT type and its 0x6e member bin attr. The console fills 0x6e in its own 0x3200/0x3201 request with
// 4 bytes that are its public IPv4 address (seen on hardware: 37.228.205.125), and 0x13 with a small number taken as its NAT type
// (inferred); handing them back per member is how a console learns where its peers are.
func MemberOf(m MemberInfo) []byte {
	b := binary.BigEndian.AppendUint16(nil, MemberID(m.No))
	b = append(b, make([]byte, 8)...) // join date
	var flag uint32
	if m.Owner {
		flag = OwnerFlag
	}
	b = binary.BigEndian.AppendUint32(b, flag)
	b = append(b, m.NAT, 0) // nat type, team id
	nick := m.Nick
	if nick == "" {
		nick = m.Name
	}
	nm := make([]byte, 48)
	copy(nm, nick)
	addr := m.Addr
	if len(addr) > 8 {
		addr = addr[:8]
	}
	b = append(b, TLV(0x0b, 0, NpID(m.Name, m.Country))...)
	b = append(b, TLV(0x0c, 1, nm)...)
	b = append(b, TLV(0x0d, 1, nil)...)
	b = append(b, TLV(0x59, 0, binAttr(0, false, m.Bin))...)
	b = append(b, TLV(0x6e, 2, addr)...)
	return TLV(0x4b, 0, b)
}

// CreateJoinRoomReply holds the five required elements of the 0x3200 reply.
func CreateJoinRoomReply(roomID uint64, rd RoomData, me MemberInfo, tok24, tok21 []byte) [][]byte {
	rd.RoomID = roomID
	id := binary.BigEndian.AppendUint64(nil, roomID)
	return [][]byte{TLV(0x24, 2, tok24), TLV(0x3a, 2, id), TLV(0x21, 2, tok21), rd.Element(), MemberOf(me)}
}

// SearchItem is one 0x45 item of a SearchRoom reply (RoomDataExternal). Wire layout from vsh 0x2bd548: three u16 (the room id's low 48 bits),
// u32 (flag attr, inferred), u16 (max slot, inferred), the owner's 24-byte NpId, then TLVs; 0x41 (32 bytes) is required.
type SearchItem struct {
	RoomID       uint64
	MaxSlot      uint16
	Owner        string
	OwnerCountry string
	Attrs        RoomAttrs // the external bins and searchable ints the host set (0x4c-0x53, 0x55, 0x56)
	Extra        []byte    // TLVs appended as they are (GetRoomDataExternalList: the owner info 0x0b, 0x0c, 0x0d the firmware asks for)
}

func (r SearchItem) element() []byte {
	b := make([]byte, 0, 0x24+36)
	b = binary.BigEndian.AppendUint16(b, uint16(r.RoomID>>32))
	b = binary.BigEndian.AppendUint16(b, uint16(r.RoomID>>16))
	b = binary.BigEndian.AppendUint16(b, uint16(r.RoomID))
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint16(b, r.MaxSlot)
	b = append(b, NpID(r.Owner, r.OwnerCountry)...)
	b = append(b, TLV(0x41, 7, make([]byte, 32))...)
	b = append(b, r.Attrs.externalItems()...)
	b = append(b, r.Extra...)
	return TLV(0x45, 0, b)
}

// SearchRoomReply is the 0x03 element: [u16 0x0045][u16 count][u16 start][u16 total] + items (vsh 0x2bdaa8).
func SearchRoomReply(items []SearchItem) []byte {
	b := []byte{0x00, 0x45, byte(len(items) >> 8), byte(len(items)), 0, 0, byte(len(items) >> 8), byte(len(items))}
	for _, it := range items {
		b = append(b, it.element()...)
	}
	return TLV(0x03, 0, b)
}

// JoinRoomReply holds the six required elements of a 0x3201 reply (vsh 0x2c602c): 0x16 my member id, tokens, room id, room data, and 0x02 = list of
// every member (0x4b).
func JoinRoomReply(myMember uint32, roomID uint64, rd RoomData, members []MemberInfo, tok24, tok21 []byte) [][]byte {
	rd.RoomID = roomID
	id := binary.BigEndian.AppendUint64(nil, roomID)
	list := []byte{0x00, 0x4b, byte(len(members) >> 8), byte(len(members))}
	for _, m := range members {
		list = append(list, MemberOf(m)...)
	}
	return [][]byte{TLV(0x16, 4, binary.BigEndian.AppendUint16(nil, MemberID(myMember))), TLV(0x24, 2, tok24), TLV(0x3a, 2, id), TLV(0x21, 2, tok21), rd.Element(), TLV(0x02, 0, list)}
}

// MemberInfo is one room member as the wire shows it: Name is the NpId online id, Country the account country its NpId realm
// comes from, Nick the display name (default Name), Addr the member's 0x6e bytes (its public IPv4 for a PS3) and NAT its NAT type.
type MemberInfo struct {
	No      uint32
	Name    string
	Country string
	Nick    string
	Addr    []byte
	NAT     byte
	Owner   bool   // flag attr bit 31 (OwnerFlag)
	Bin     []byte // the member's 0x59 bin attr (the game's local-player mask; none for Terraria)
}
