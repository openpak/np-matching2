package wire

import "encoding/binary"

// Room and member attributes as a console writes and reads them. The attribute id is the TLV element id (vsh request builders 0x2b9628
// room bin attr internal, 0x2b9ca0 external bin attr, 0x2b9d60 searchable int attr, 0x2b9754 member bin attr; reply slot parser 0x2c3c3c
// stores the element id as the attr id), so no id lives inside the value.
const (
	AttrIntFirst = 0x4c // searchable int attrs 0x4c..0x53 (u32)
	AttrIntLast  = 0x53
	AttrExt1     = 0x55 // external bin attr 1 (0..256 bytes, raw in the element)
	AttrExt2     = 0x56
	AttrExtra    = 0x6c // the host's external info (12 bytes a real PS3 sets in its 0x1202: its public IPv4, 4 zero bytes, 0a57 0007); kept and echoed
	AttrInt1     = 0x57 // internal bin attr 1: [u16 last-update member id][8 byte time][TLV 0x01 data], data 0..256
	AttrInt2     = 0x58
	AttrMember   = 0x59 // member bin attr internal 1: [8 byte time][TLV 0x01 data]
	// AttrSigOpt is the room's SceNpMatching2SignalingOptParam (type u8: 1 mesh, 2 star; flag u8, bit 0 manual mode; u16 hub member id, 0 =
	// owner; 4 reserved), sent by the host in its 0x3200 request (Terraria 01.12 = 01 00.., Minecraft 01.84 = 02 00..). The firmware takes it
	// back only from the reply's room data internal 0x6d (vsh 0x29cb6c -> room+0x48), and its signalling manager (vsh 0x1e4950, read via
	// 0x288bf4 for attr 0x6d) activates connections toward members only for type 1 or 2 (0x1e4274). Returned empty, no PS3 ever signals.
	AttrSigOpt = 0x6d
)

// RoomAttrs are the attribute values a console set on a room, by attribute id: Bin the external and internal bins (0x55-0x58) and the
// signalling option (0x6d), Int the searchable ints (0x4c-0x53).
type RoomAttrs struct {
	Bin map[uint16][]byte
	Int map[uint16]uint32
}

// Empty reports whether no attribute is set.
func (a RoomAttrs) Empty() bool { return len(a.Bin) == 0 && len(a.Int) == 0 }

// Merge returns a with every attribute of o set over it (a console's update changes only the attributes it names).
func (a RoomAttrs) Merge(o RoomAttrs) RoomAttrs {
	out := RoomAttrs{Bin: map[uint16][]byte{}, Int: map[uint16]uint32{}}
	for k, v := range a.Bin {
		out.Bin[k] = v
	}
	for k, v := range a.Int {
		out.Int[k] = v
	}
	for k, v := range o.Bin {
		out.Bin[k] = v
	}
	for k, v := range o.Int {
		out.Int[k] = v
	}
	return out
}

// tlv1 reads the TLV 0x01 (the attribute data) at the start of b.
func tlv1(b []byte) ([]byte, bool) {
	if len(b) < 4 || binary.BigEndian.Uint16(b)&0xfff != 1 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if 4+n > len(b) {
		return nil, false
	}
	return b[4 : 4+n], true
}

// RoomAttrs reads the room attributes a request carries (0x3200 internal bins, 0x1202 and 0x1207 external bins and ints, 0x3204 internal bins).
func (f *Frame) RoomAttrs() RoomAttrs {
	a := RoomAttrs{Bin: map[uint16][]byte{}, Int: map[uint16]uint32{}}
	for id, v := range f.Elements() {
		switch {
		case id >= AttrIntFirst && id <= AttrIntLast && len(v) == 4:
			a.Int[id] = binary.BigEndian.Uint32(v)
		case id == AttrExt1 || id == AttrExt2 || (id == AttrSigOpt || id == AttrExtra) && len(v) > 0 && len(v) <= 64:
			a.Bin[id] = append([]byte{}, v...)
		case id == AttrInt1 || id == AttrInt2:
			if len(v) >= 10 {
				if d, ok := tlv1(v[10:]); ok {
					a.Bin[id] = append([]byte{}, d...)
				}
			}
		}
	}
	return a
}

// MemberAttr reads the member bin attr 0x59 of a request (JoinRoom, SetRoomMemberDataInternal): the game's local-player mask, 4 bytes.
func (f *Frame) MemberAttr() ([]byte, bool) {
	v, ok := f.Elements()[AttrMember]
	if !ok || len(v) < 8 {
		return nil, false
	}
	d, ok := tlv1(v[8:])
	return append([]byte{}, d...), ok
}

// internalAttr is one internal bin attr element of a room data or event: [u16 last-update member id][8 byte time][TLV 0x01 data].
func internalAttr(id uint16, lastMember uint16, data []byte) []byte {
	return TLV(id, 0, binAttr(lastMember, true, data))
}

// externalItems are the attribute TLVs of a RoomDataExternal item: searchable ints then the external bins, in id order.
func (a RoomAttrs) externalItems() []byte {
	var b []byte
	for id := uint16(AttrIntFirst); id <= AttrIntLast; id++ {
		if v, ok := a.Int[id]; ok {
			b = append(b, TLV(id, 5, binary.BigEndian.AppendUint32(nil, v))...)
		}
	}
	for _, id := range []uint16{AttrExt1, AttrExt2, AttrExtra} {
		if v, ok := a.Bin[id]; ok {
			b = append(b, TLV(id, 2, v)...)
		}
	}
	return b
}

// SearchFilter is one int attribute condition of a SearchRoom request: the element 0x06 = [u32 operator][TLV attr id (u32 value)].
type SearchFilter struct {
	Attr  uint16
	Op    uint32 // SceNpMatching2Operator: 1 EQ, 2 NE, 3 LT, 4 LE, 5 GT, 6 GE (SDK order, inferred)
	Value uint32
}

// SearchFilters reads the int filters of a 0x1200/0x120c request (vsh builder 0x2b9bb8, called once per filter).
func (f *Frame) SearchFilters() []SearchFilter {
	var out []SearchFilter
	for _, v := range f.All(0x06) {
		if len(v) != 12 {
			continue
		}
		id := binary.BigEndian.Uint16(v[4:]) & 0xfff
		if id < AttrIntFirst || id > AttrIntLast || binary.BigEndian.Uint16(v[6:]) != 4 {
			continue
		}
		out = append(out, SearchFilter{Attr: id, Op: binary.BigEndian.Uint32(v), Value: binary.BigEndian.Uint32(v[8:])})
	}
	return out
}

// RoomDataUpdated is the kind-4 UpdatedRoomDataInternal event (0x320e; vsh handler 0x2c8124 raises 0x1106 when the header u32 at +8 is 0):
// the two internal bin attrs as they now stand, and the 0x3a room id (the owner answers with 0x120a, vsh 0x2c8528). lastMember is the wire
// id of the member that wrote them.
func RoomDataUpdated(key []byte, roomID uint64, lastMember uint16, a1, a2 []byte) []byte {
	return Event(key, EventRoomUpdated, lastMember, roomIDElem(roomID), internalAttr(AttrInt1, lastMember, a1), internalAttr(AttrInt2, lastMember, a2))
}

// MemberDataUpdated is the kind-4 UpdatedRoomMemberDataInternal event (0x320d; handler 0x2c85ac raises 0x1107): the member's id and its 0x59.
func MemberDataUpdated(key []byte, memberID uint16, bin []byte) []byte {
	return Event(key, EventMemberUpdated, memberID, TLV(0x16, 4, binary.BigEndian.AppendUint16(nil, memberID)), TLV(AttrMember, 0, binAttr(0, false, bin)))
}

// SetRoomDataInternalReply is the 0x3204 reply: the required 0x70 (update time, 0 = unset, which the firmware keeps 0).
func SetRoomDataInternalReply() [][]byte { return [][]byte{TLV(0x70, 6, make([]byte, 8))} }

// RoomDataExternalList is the 0x02 element of a 0x1208 reply: [u16 0x0045][u16 count] + the 0x45 items, the same item as a SearchRoom
// result (vsh parser 0x2bd8a8 reads it with the item parser 0x2bd548).
func RoomDataExternalList(items []SearchItem) []byte {
	b := []byte{0x00, 0x45, byte(len(items) >> 8), byte(len(items))}
	for _, it := range items {
		b = append(b, it.element()...)
	}
	return TLV(0x02, 0, b)
}
