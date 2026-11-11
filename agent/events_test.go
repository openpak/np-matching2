package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
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
	if o := ownerOf([]RoomMember{{No: 1, Owner: true}, {No: 3}, {No: 2}}, 1); o == nil || o.No != 2 {
		t.Fatalf("owner after the owner left: %+v", o)
	}
	if o := ownerOf([]RoomMember{{No: 1}, {No: 3, Owner: true}, {No: 2}}, 0); o == nil || o.No != 3 {
		t.Fatalf("flagged owner: %+v", o)
	}
	if ownerOf([]RoomMember{{No: 1}}, 1) != nil {
		t.Fatal("nobody left")
	}
	if causeOf("leave") != 1 || causeOf("kicked") != 2 || causeOf("expired") != 5 {
		t.Fatal("causes")
	}
}

// The owner's 0x1203 follow-up to a MemberJoined, as a real PS3 hosting Minecraft 01.84 sent it (2026-11-11 15:21:40Z, request id
// 0x11a00031 = caller 1, type 0x1a, sequence 0x031; +12 is its login's session id; body = the 0x3a our event carried), here MAC'd with a
// test key. Its done never completes it (vsh 0x299364), so it gets ALREADY_JOINED, which ends it at once; the same command as the last
// step of a JoinRoom (type 0x0a), the 0x1204 of a leave and the owner's 0x1204/0x120a follow-ups get an empty success.
func TestOwnerFollowUpsAnswered(t *testing.T) {
	a, _, st := testAgent()
	a.Titles = map[string]Title{"NPWR05636_00": mcTitle}
	st.comm = "NPWR05636_00"
	req := func(cmd uint16, id uint32) *wire.Frame {
		b, _ := hex.DecodeString("1101002c1203000011a000310000007a00000000000000000000000000000000203a000800018cc2817199b8")
		binary.BigEndian.PutUint16(b[4:], cmd)
		binary.BigEndian.PutUint32(b[8:], id)
		copy(b[16:32], wire.Mac(st.sess.Key, b))
		f, _, err := wire.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	f := req(0x1203, 0x11a00031)
	if wire.ReqType(f.ReqID) != wire.ReqTypeMemberJoinedNotice || !bytes.Equal(f.Elements()[0x3a], []byte{0, 1, 0x8c, 0xc2, 0x81, 0x71, 0x99, 0xb8}) {
		t.Fatalf("recorded request: type %#x", wire.ReqType(f.ReqID))
	}
	out := a.handle0(context.Background(), st, f)
	if got := hex.EncodeToString(out); got != "110200201203300011a00031000000002cc26dfb10cdab014b01a12ff6c4e2bf" {
		t.Errorf("0x1203 type 0x1a reply %s", got)
	}
	for _, c := range []struct {
		cmd uint16
		id  uint32
	}{{0x1203, 0x20a00012}, {0x1204, 0x20b00013}, {0x1204, 0x11b00032}, {0x120a, 0x11c00033}} {
		if r := reply(t, a.handle0(context.Background(), st, req(c.cmd, c.id))); r.Result != 0 || len(r.Body) != 0 || r.Cmd != c.cmd {
			t.Errorf("%#x type %#x: result %#x body %x", c.cmd, c.id>>20&0xff, r.Result, r.Body)
		}
	}
}
