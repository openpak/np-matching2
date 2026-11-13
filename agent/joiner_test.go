package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"openpak/np-matching2/wire"
)

// Golden requests from the recorder (scratch/ps3-signaling-2026-11-09/matching2-2026-11-13.jsonl, prds#177): the real PS3's 0x1209 for
// a JoinRoom of the bridged room 0x0001e8ca9e01df86 (16:32:05.170, request id 0x20a00041, 50 bytes) and a real host's (15:54:06.544,
// 0x20900014, 38 bytes), whole frames as recorded (the MAC is the session's; nothing here verifies it).
const (
	goldJoin1209 = "110100321209000020a00041000000941fb0b9d65be268bf6312b82fe1145cd140290002e8ca402e00029e01403d0002df86"
	goldHost1209 = "1101002612090000209000140000008b2259cad82940701ee2c831e7f1fd2e02402900020001"
)

func recorded(t *testing.T, h string) *wire.Frame {
	b, _ := hex.DecodeString(h)
	f, _, err := wire.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// vsh 0x29ad94: a JoinRoom's room connection goes to the 0x1f endpoint (req+6), a CreateJoinRoom's to the 0x02 list. The 2026-11-13 reply
// had no 0x1f, so the joiner's connection had no host, no 0x3201 followed and the game destroyed its server context (0x1005).
func TestJoinRoom1209NamesTheRoomServer(t *testing.T) {
	a, _, st := testAgent()
	a.RoomHost, a.RoomPort = "145.241.199.19", 3480
	f := reply(t, a.worldServer(a.log(), st, recorded(t, goldJoin1209)))
	got := hex.EncodeToString(f.Elements()[0x1f])
	// u8 u16 u8 header, then 0x0a { port 0x0d98, 0x09 host }: the same endpoint item the 0x02 list carries
	if want := "00000000000a00140d981009000e3134352e3234312e3139392e3139"; got != want {
		t.Fatalf("0x1f\n got %s\nwant %s", got, want)
	}
	if v := f.Elements()[0x20]; len(v) != 16 {
		t.Fatalf("0x20 token (required, echoed in 0x3201) %x", v)
	}
	// schema order 0x3d, 0x1f, 0x20, 0x02
	var order []uint16
	for _, e := range walkTLVs(f.Body) {
		order = append(order, e.id)
	}
	if len(order) != 4 || order[0] != 0x3d || order[1] != 0x1f || order[2] != 0x20 || order[3] != 0x02 {
		t.Fatalf("order %x", order)
	}

	// a host's reply stays what the 15:54 and 16:16 hosts accepted: 0x3d, 0x20, the 0x02 list, no 0x1f
	h := reply(t, a.worldServer(a.log(), st, recorded(t, goldHost1209)))
	if _, ok := h.Elements()[0x1f]; ok {
		t.Fatal("host reply carries 0x1f")
	}
	if got := hex.EncodeToString(h.Elements()[0x02]); got != "000a0001000a00140d981009000e3134352e3234312e3139392e3139" {
		t.Fatalf("host list %s", got)
	}
}

// The 0x3201 the firmware then sends on the new connection (builder vsh 0x2c63ac): 0x23, 0x5d, 0x3e = room id bits 15..0, 0x13, 0x59,
// 0x6e, 0x20; no 0x29/0x2e. It must find the bridged room by 0x3e alone even when other rooms are open.
func TestFirmwareJoinRoomFindsTheRoomByItsLowPart(t *testing.T) {
	t.Setenv("NP_BRIDGE_KEY", "bk")
	a, r, st := bridgeAgent()
	r.list = append([]RoomInfo{r.list[0]}, bridgedRoom())
	r.list[0].RoomID = 1<<48 | 0x111111110000
	r.list[0].ID, r.list[0].Bridge = "11111111-0000-0000-0000-000000000000", ""
	a.Rooms = bridgedRooms{r}
	tok := bytes.Repeat([]byte{0xab}, 16)
	req := frame(0x3201, wire.TLV(0x23, 2, tok), wire.TLV(0x5d, 2, tok), wire.TLV(0x3e, 4, []byte{0xc5, 0x8c}), wire.TLV(0x13, 0, []byte{2}),
		reqMember([]byte{0, 0, 0, 1}), wire.TLV(0x6e, 2, []byte{10, 0, 0, 2}), wire.TLV(0x20, 2, tok))
	f := reply(t, a.joinRoom(context.Background(), a.log(), mcTitle, st, req))
	if f.Result != 0 || !bytes.Equal(f.Elements()[0x3a], binary.BigEndian.AppendUint64(nil, bridgedRoomID)) {
		t.Fatalf("result %d room %x", f.Result, f.Elements()[0x3a])
	}
}
