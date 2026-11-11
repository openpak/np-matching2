package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"openpak/np-matching2/wire"
)

func reqInt(id uint16, data []byte) []byte {
	return wire.TLV(id, 0, append(make([]byte, 10), wire.TLV(1, 2, data)...))
}
func reqMember(data []byte) []byte {
	return wire.TLV(0x59, 0, append(make([]byte, 8), wire.TLV(1, 2, data)...))
}

var mcTitle = Title{Key: "minecraft", Compat: "lce-ps3-0884", Status: 1}

func reply(t *testing.T, out []byte) *wire.Frame {
	t.Helper()
	f, _, err := wire.Parse(out)
	if out == nil || err != nil || f == nil {
		t.Fatalf("no reply: %v", err)
	}
	return f
}

// Terraria's room keeps its compat group and sends no attributes; Minecraft's gets its own group and its attributes reach the core.
func TestCreateRoomCarriesTheTitlesGroupAndAttrs(t *testing.T) {
	b57, b58 := bytes.Repeat([]byte{0x57}, 128), bytes.Repeat([]byte{0x58}, 128)
	a, r, st := testAgent()
	out := a.createRoom(context.Background(), a.log(), mcTitle, st, frame(0x3200, wire.TLV(0x3f, 4, []byte{0, 8}), reqInt(0x57, b57), reqInt(0x58, b58), reqMember([]byte{0, 0, 0, 1})))
	f := reply(t, out)
	if r.created.compat != "lce-ps3-0884" || !bytes.Equal(r.created.attrs.Bin[wire.AttrInt1], b57) || !bytes.Equal(r.created.bin, []byte{0, 0, 0, 1}) {
		t.Fatalf("core got %+v", r.created)
	}
	if rd := f.Elements()[0x71]; !bytes.Contains(rd, b57) || !bytes.Contains(rd, b58) {
		t.Fatal("room data lacks the bins")
	}
	if !bytes.Contains(f.Elements()[0x4b], wire.TLV(1, 2, []byte{0, 0, 0, 1})) {
		t.Fatal("host member lacks its 0x59")
	}
	a.createRoom(context.Background(), a.log(), Title{Key: "terraria"}, st, frame(0x3200, wire.TLV(0x3f, 4, []byte{0, 8})))
	if r.created.compat != "old-gen-1.2.4" || !r.created.attrs.Empty() || r.created.bin != nil {
		t.Fatalf("terraria room %+v", r.created)
	}
}

func TestSearchPassesTheTitlesGroupAndFilters(t *testing.T) {
	a, r, st := testAgent()
	flt := wire.TLV(0x06, 0, append([]byte{0, 0, 0, 5}, wire.TLV(0x4c, 5, []byte{0, 0, 0, 2})...))
	a.searchRooms(context.Background(), a.log(), mcTitle, st, frame(0x1200, flt))
	if len(r.filters) != 1 || r.filters[0] != (wire.SearchFilter{Attr: 0x4c, Op: 5, Value: 2}) {
		t.Fatalf("filters %+v", r.filters)
	}
}

func hostedRoom(r *rooms) {
	r.room = JoinedRoom{ID: "r", Max: 8, Members: []RoomMember{{No: 1, Account: "acc-host", Owner: true, Bin: []byte{0, 0, 0, 1}}, {No: 2, Account: "acc-me", Bin: []byte{0, 0, 0, 2}}}}
}

func TestRoomDataInternalIsStoredAndAnswered(t *testing.T) {
	a, r, st := testAgent()
	hostedRoom(r)
	st.room = "r"
	nb := bytes.Repeat([]byte{9}, 128)
	f := reply(t, a.setRoomInternal(context.Background(), a.log(), st, frame(0x3204, wire.TLV(0x06, 0, make([]byte, 12)), reqInt(0x57, nb)), st.sess.Key))
	if len(r.setAttrs) != 1 || !bytes.Equal(r.setAttrs[0].Bin[wire.AttrInt1], nb) || len(f.Elements()[0x70]) != 8 {
		t.Fatalf("stored %+v, reply %x", r.setAttrs, f.Raw)
	}
}

func TestMemberDataSetReadAndKick(t *testing.T) {
	a, r, st := testAgent()
	hostedRoom(r)
	st.room = "r"
	ctx := context.Background()
	// SetRoomMemberDataInternal for member id 0x20 = slot 2 = acc-me
	if f := reply(t, a.setMemberData(ctx, a.log(), st, frame(0x3206, wire.TLV(0x16, 4, []byte{0, 0x20}), reqMember([]byte{0, 0, 0, 3})), st.sess.Key)); f.Result != 0 || !bytes.Equal(r.memberBin["acc-me"], []byte{0, 0, 0, 3}) {
		t.Fatalf("member bin %v", r.memberBin)
	}
	// without 0x16 the caller's own member
	a.setMemberData(ctx, a.log(), st, frame(0x3206, reqMember([]byte{0, 0, 0, 4})), st.sess.Key)
	if !bytes.Equal(r.memberBin["acc-me"], []byte{0, 0, 0, 4}) {
		t.Fatalf("own member bin %v", r.memberBin)
	}
	// GetRoomMemberDataInternal answers one 0x4b with the stored 0x59
	f := reply(t, a.getMemberData(ctx, a.log(), st, frame(0x3207, wire.TLV(0x16, 4, []byte{0, 0x10})), st.sess.Key))
	if me := f.Elements()[0x4b]; !bytes.Contains(me, wire.TLV(1, 2, []byte{0, 0, 0, 1})) || !bytes.Contains(me, []byte{0x80, 0, 0, 0}) {
		t.Fatalf("member %x", me)
	}
	// a member that is not in the room gets no answer (the game times out), never a wrong member
	if a.getMemberData(ctx, a.log(), st, frame(0x3207, wire.TLV(0x16, 4, []byte{0, 0x50})), st.sess.Key) != nil {
		t.Fatal("answered for a member that is not in the room")
	}
	reply(t, a.kickout(ctx, a.log(), st, frame(0x3211, wire.TLV(0x16, 4, []byte{0, 0x20}), wire.TLV(0x17, 3, []byte{0})), st.sess.Key))
	if len(r.kicked) != 1 || r.kicked[0] != "acc-me" {
		t.Fatalf("kicked %v", r.kicked)
	}
}

func TestExternalDataAndList(t *testing.T) {
	a, r, st := testAgent()
	st.room = "r"
	ctx := context.Background()
	b55, b56 := bytes.Repeat([]byte{0x55}, 92), bytes.Repeat([]byte{0x56}, 92)
	reply(t, a.setExternal(ctx, a.log(), st, frame(0x1207, wire.TLV(0x29, 4, []byte{0, 1}), wire.TLV(0x55, 2, b55), wire.TLV(0x4c, 5, []byte{0, 0, 0, 3}))))
	if len(r.setAttrs) != 1 || !bytes.Equal(r.setAttrs[0].Bin[wire.AttrExt1], b55) || r.setAttrs[0].Int[0x4c] != 3 {
		t.Fatalf("stored %+v", r.setAttrs)
	}
	// 0x1208 names the room by one u16 of its id and the attrs it wants; only those come back
	r.list[0].Attrs = wire.RoomAttrs{Bin: map[uint16][]byte{wire.AttrExt1: b55, wire.AttrExt2: b56, wire.AttrInt1: b55}, Int: map[uint16]uint32{0x4c: 3, 0x4d: 4}}
	req := func(ids ...[]byte) *wire.Frame {
		return frame(0x1208, append([]([]byte){wire.TLV(0x29, 4, []byte{0, 1}), wire.TLV(0x3d, 4, []byte{0x11, 0x11}), wire.TLV(0x05, 4, []byte{0, 0x55}), wire.TLV(0x05, 4, []byte{0, 0x4c})}, ids...)...)
	}
	f := reply(t, a.roomDataExternalList(ctx, a.log(), mcTitle, st, req()))
	list := f.Elements()[0x02]
	if list[3] != 1 || !bytes.Contains(list, b55) || bytes.Contains(list, b56) || !bytes.Contains(list, wire.TLV(0x4c, 5, []byte{0, 0, 0, 3})) || bytes.Contains(list, wire.TLV(0x4d, 5, []byte{0, 0, 0, 4})) {
		t.Fatalf("list %x", list)
	}
	// a room that is not named is not listed
	other := frame(0x1208, wire.TLV(0x29, 4, []byte{0, 1}), wire.TLV(0x3d, 4, []byte{0x77, 0x77}))
	if list := reply(t, a.roomDataExternalList(ctx, a.log(), mcTitle, st, other)).Elements()[0x02]; list[3] != 0 {
		t.Fatalf("unnamed room listed: %x", list)
	}
}

// The 0x1001 status byte is per title: Terraria keeps the verified 0, Minecraft PS3 gets 1.
func TestServerStatusIsPerTitle(t *testing.T) {
	a, _, _ := testAgent()
	pass := bytes.Repeat([]byte{7}, 128)
	a.Titles = map[string]Title{"TERRARIA": {Key: "terraria", Pass: pass}, "MINECRAFT": {Key: "minecraft", Pass: pass, Status: 1}}
	for comm, want := range map[string]byte{"TERRARIA": 0, "MINECRAFT": 1} {
		f, _, _ := wire.Parse(wire.Request(pass[:16], wire.CmdPing, [4]byte{}, wire.TLV(0x10, 1, []byte(comm)), wire.TLV(0x73, 4, []byte{0, 1})))
		got := reply(t, a.handle0(context.Background(), &conn{stop: make(chan struct{})}, f)).Elements()[0x1d]
		if !bytes.Equal(got, []byte{0, 1, want}) {
			t.Fatalf("%s: 0x1d = %x", comm, got)
		}
	}
}

// The host's signalling option (0x6d in its 0x3200, recorded from the real PS3 2026-11-11: Terraria 01.12 mesh, Minecraft 01.84 star) must
// come back in the room data of the create reply and of every join reply: the firmware's signalling manager reads it only from there (vsh
// 0x1e4950 -> 0x288bf4) and activates toward room members only for type 1 or 2 (0x1e4274). Empty, the PS3 host never offers (runs 7-9, mc1/mc2).
func TestSignalingOptionIsEchoedInRoomData(t *testing.T) {
	for _, c := range []struct {
		title Title
		opt   string
	}{{Title{Key: "terraria"}, "0100000000000000"}, {mcTitle, "0200000000000000"}} {
		opt, _ := hex.DecodeString(c.opt)
		a, r, st := testAgent()
		f := reply(t, a.createRoom(context.Background(), a.log(), c.title, st, frame(0x3200, wire.TLV(0x3f, 4, []byte{0, 8}), wire.TLV(0x6d, 2, opt))))
		want := wire.TLV(0x6d, 2, opt)
		if !bytes.Contains(f.Elements()[0x71], want) {
			t.Fatalf("%s: create reply room data lacks %x", c.title.Key, want)
		}
		if !bytes.Equal(r.created.attrs.Bin[wire.AttrSigOpt], opt) {
			t.Fatalf("%s: core did not keep the option: %+v", c.title.Key, r.created.attrs)
		}
		if !bytes.Contains(roomData(r.created.attrs, 8, 0x10).Element(), want) {
			t.Fatalf("%s: join room data lacks the option", c.title.Key)
		}
	}
	if got := bridgedAttrs(make([]byte, extLen), make([]byte, intLen)).Bin[wire.AttrSigOpt]; !bytes.Equal(got, []byte{2, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("bridged room option %x", got)
	}
}
