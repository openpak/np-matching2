package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func h(s string) []byte { b, _ := hex.DecodeString(s); return b }

// A real 0x1001 request captured from Terraria (BLES01938) on firmware 4.93 in Pier, 2026-11-05.
func TestRealPing(t *testing.T) {
	pkt := h("1101003610010000101000010000000006" + "7c6091c2d77a8fee815d95641ed1bd" + "1010000c4e50575230343237305f3030" + "40730002" + "0001")
	f, rest, err := Parse(pkt)
	if err != nil || len(rest) != 0 || f.Cmd != CmdPing || f.Kind != KindRequest {
		t.Fatalf("%v %v", err, f)
	}
	key := h("0b6476018b974b55ff338d8ba299c624")
	if !f.Verify(key) || f.Verify(key[:15]) {
		t.Fatal("MAC of the captured request")
	}
	if string(f.Elements()[0x10]) != "NPWR04270_00" {
		t.Fatal("commId")
	}
}

func TestKeepaliveAndReply(t *testing.T) {
	f, rest, err := Parse([]byte{0, 0x11})
	if err != nil || f != nil || len(rest) != 1 {
		t.Fatal("keepalive")
	}
	key := bytes.Repeat([]byte{7}, 20)
	r := Reply(key, CmdWorldList, 0, [4]byte{1, 2, 3, 4}, WorldList([]World{{ID: 1}}))
	g, _, err := Parse(r)
	if err != nil || !g.Verify(key) || g.ReqID != [4]byte{1, 2, 3, 4} {
		t.Fatal("reply roundtrip")
	}
	if len(g.Elements()[0x02]) != 4+4+18 {
		t.Fatalf("world list %d", len(g.Elements()[0x02]))
	}
}

func TestServerList(t *testing.T) {
	b := ServerList("matching.example", 3480)
	// 0x02 header (4) + list header (4) + 0x0a header (4) + port (2) + 0x09 header (4) + 16 host bytes
	if len(b) != 4+4+4+2+4+16 {
		t.Fatalf("len %d", len(b))
	}
	el := (&Frame{Body: b}).Elements()
	if len(el[0x02]) != 4+4+2+4+16 || el[0x02][3] != 1 {
		t.Fatalf("list %x", el[0x02])
	}
}

func TestNpIDRealm(t *testing.T) {
	if got := string(NpID("PS3Test", "PT")[16:]); got != "ptptps3\x00" {
		t.Fatalf("pt: %q", got)
	}
	if got := string(NpID("SwitchTest", "")[16:]); got != "ususps3\x00" {
		t.Fatalf("default: %q", got)
	}
}
