package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// request form of the attributes (vsh builders 0x2b9628, 0x2b9ca0, 0x2b9d60, 0x2b9754)
func reqInt(id uint16, data []byte) []byte {
	return TLV(id, 0, append(make([]byte, 10), TLV(1, 2, data)...))
}
func reqMember(data []byte) []byte {
	return TLV(AttrMember, 0, append(make([]byte, 8), TLV(1, 2, data)...))
}

func frameOf(els ...[]byte) *Frame {
	f, _, _ := Parse(Request(make([]byte, 20), 0x3200, [4]byte{}, els...))
	return f
}

func TestParseAttrs(t *testing.T) {
	a57, a55 := bytes.Repeat([]byte{0x57}, 128), bytes.Repeat([]byte{0x55}, 92)
	f := frameOf(reqInt(0x57, a57), reqInt(0x58, []byte{1, 2}), TLV(0x55, 2, a55), TLV(0x56, 2, nil), TLV(0x4c, 5, []byte{0, 0, 0, 7}), TLV(0x53, 5, []byte{0xff, 0, 0, 1}), reqMember([]byte{0, 0, 0, 1}))
	a := f.RoomAttrs()
	if !bytes.Equal(a.Bin[AttrInt1], a57) || !bytes.Equal(a.Bin[AttrInt2], []byte{1, 2}) || !bytes.Equal(a.Bin[AttrExt1], a55) || len(a.Bin[AttrExt2]) != 0 {
		t.Fatalf("bins %v", a.Bin)
	}
	if _, ok := a.Bin[AttrExt2]; !ok {
		t.Fatal("an empty external bin is still set")
	}
	if a.Int[0x4c] != 7 || a.Int[0x53] != 0xff000001 || len(a.Int) != 2 {
		t.Fatalf("ints %v", a.Int)
	}
	if m, ok := f.MemberAttr(); !ok || !bytes.Equal(m, []byte{0, 0, 0, 1}) {
		t.Fatalf("member attr %x %v", m, ok)
	}
	// nothing set: Terraria's 0x3200 carries none of them
	if g := frameOf(TLV(0x3f, 4, []byte{0, 8}), TLV(0x6e, 2, []byte{1, 2, 3, 4})); !g.RoomAttrs().Empty() {
		t.Fatal("attrs from a request that has none")
	} else if _, ok := g.MemberAttr(); ok {
		t.Fatal("member attr from a request that has none")
	}
	// a truncated internal bin is skipped, not a panic
	if g := frameOf(TLV(0x57, 0, []byte{0, 0, 0})); !g.RoomAttrs().Empty() {
		t.Fatal("truncated 0x57 accepted")
	}
	m := RoomAttrs{Bin: map[uint16][]byte{AttrInt1: {1}}, Int: map[uint16]uint32{0x4c: 1}}.Merge(RoomAttrs{Bin: map[uint16][]byte{AttrInt2: {2}}, Int: map[uint16]uint32{0x4c: 9}})
	if len(m.Bin) != 2 || m.Int[0x4c] != 9 {
		t.Fatalf("merge %v", m)
	}
}

func TestSearchFilters(t *testing.T) {
	flt := func(op uint32, attr uint16, v uint32) []byte {
		return TLV(0x06, 0, append(binary.BigEndian.AppendUint32(nil, op), TLV(attr, 5, binary.BigEndian.AppendUint32(nil, v))...))
	}
	f := frameOf(flt(1, 0x4c, 7), flt(6, 0x4d, 2), TLV(0x06, 0, []byte{1, 2, 3}), flt(1, 0x20, 5))
	got := f.SearchFilters()
	if len(got) != 2 || got[0] != (SearchFilter{0x4c, 1, 7}) || got[1] != (SearchFilter{0x4d, 6, 2}) {
		t.Fatalf("filters %+v", got)
	}
}

// TestAttrRepliesGolden pins the bytes of every reply and event this file adds. Like TestCreateJoinReplyGolden, change them only after the
// firmware path says so and a console accepted them.
func TestAttrRepliesGolden(t *testing.T) {
	key := []byte("room-key-16bytes")
	rid := [4]byte{0, 0, 0, 9}
	a1, a2 := bytes.Repeat([]byte{0x57}, 4), bytes.Repeat([]byte{0x58}, 4)
	ext := RoomAttrs{Bin: map[uint16][]byte{AttrExt1: {0xa1, 0xa2}, AttrExt2: {0xb1}}, Int: map[uint16]uint32{0x4d: 2, 0x4c: 7}}
	item := SearchItem{RoomID: 0x0001aaaabbbbcccc, MaxSlot: 8, Owner: "Host", OwnerCountry: "pt", Attrs: ext}
	rd := RoomData{WorldID: 1, MaxSlot: 8, RoomID: 0x0001aaaabbbbcccc, Attr1: a1, Attr2: a2, LastMember: 0x10}
	me := MemberInfo{No: 1, Name: "Host", Country: "pt", Owner: true, Bin: []byte{0, 0, 0, 1}}
	for _, c := range []struct {
		name string
		got  []byte
		want string
	}{
		{"RoomDataUpdated", RoomDataUpdated(key, 0x0001aaaabbbbcccc, 0x10, a1, a2), "11040058320e000000000000000100106aa3e5650058d64de1bc5a1fde5fab25203a00080001aaaabbbbcccc0057001200100000000000000000200100045757575700580012001000000000000000002001000458585858"},
		{"MemberDataUpdated", MemberDataUpdated(key, 0x20, []byte{0, 0, 0, 3}), "1104003a320d000000000000000100201f923e1fc9745f56411fb3ee3a0f3c314016000200200059001000000000000000002001000400000003"},
		{"0x3204 reply", Reply(key, 0x3204, 0, rid, SetRoomDataInternalReply()...), "1102002c320400000000000900000000153e499cdfed45194db45cb9ee04edf6607000080000000000000000"},
		{"0x1208 reply", Reply(key, 0x1208, 0, rid, RoomDataExternalList([]SearchItem{item})), "1102008f1208000000000009000000005928cf62906093f83568581516cd553b0002006b0045000100450063aaaabbbbcccc000000000008486f73740000000000000000000000007074707470733300704100200000000000000000000000000000000000000000000000000000000000000000504c000400000007504d00040000000220550002a1a220560001b1"},
		{"0x1200 item with attrs", Reply(key, 0x1200, 0, rid, SearchRoomReply([]SearchItem{item})), "110200931200000000000009000000001d92de21a7f947a17ca17d090d21cd510003006f004500010000000100450063aaaabbbbcccc000000000008486f73740000000000000000000000007074707470733300704100200000000000000000000000000000000000000000000000000000000000000000504c000400000007504d00040000000220550002a1a220560001b1"},
		{"0x3207 reply", Reply(key, 0x3207, 0, rid, MemberOf(me)), "110200a032070000000000090000000075ad28eab51ee26f64f485cb3884a446004b007c00100000000000000000800000000000000b0018486f73740000000000000000000000007074707470733300100c0030486f73740000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100d00000059001000000000000000002001000400000001206e0000"},
		{"room data with attrs", rd.Element(), "0071007c000100000001000800000000000000000001aaaabbbbcccc00000000000000007041002000000000000000000000000000000000000000000000000000000000000000000057001200100000000000000000200100045757575700580012001000000000000000002001000458585858206d00000002000400470000"},
	} {
		if hex.EncodeToString(c.got) != c.want {
			t.Errorf("%s:\n got %x\nwant %s", c.name, c.got, c.want)
		}
	}
}
