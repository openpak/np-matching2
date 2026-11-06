package front

import (
	"crypto/tls"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

// legacyHello builds a firmware-style hello: TLS 1.0 record, 16 suites, no extension block (80 bytes in all).
func legacyHello() []byte {
	body := []byte{0x03, 0x01}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 32)
	for i := 0; i < 16; i++ {
		body = append(body, 0x00, byte(0x2f+i))
	}
	body = append(body, 1, 0)
	hs := append([]byte{0x01, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestClassifyLegacy(t *testing.T) {
	h := legacyHello()
	if len(h) != 80 {
		t.Fatalf("fixture is %d bytes, the firmware sends 80", len(h))
	}
	if Classify(h) != Legacy {
		t.Fatal("firmware-shaped hello not recognised")
	}
	if Classify(h[:40]) != Other || Classify(nil) != Other || Classify([]byte("GET / HTTP/1.1\r\n\r\n")) != Other {
		t.Fatal("truncated or non-TLS input must be Other")
	}
}

// A hello produced by Go's TLS client (extensions: supported groups, sigalgs, ...), standing in for a modern
// client such as D2R's: it must never be mistaken for the firmware.
func TestClassifyModern(t *testing.T) {
	a, b := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := b.Read(buf)
		got <- buf[:n]
		b.Close()
	}()
	go tls.Client(a, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}).Handshake()
	select {
	case rec := <-got:
		if Classify(rec) != Other {
			t.Fatal("modern hello classified as legacy")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no hello")
	}
}

func TestPeekReplays(t *testing.T) {
	a, b := net.Pipe()
	h := legacyHello()
	go func() { b.Write(append(h, []byte("tail")...)) }()
	rec, pc, err := Peek(a, time.Second)
	if err != nil || len(rec) != len(h) {
		t.Fatalf("peek %v %d", err, len(rec))
	}
	buf := make([]byte, len(h)+4)
	n := 0
	for n < len(buf) {
		m, err := pc.Read(buf[n:])
		if err != nil {
			t.Fatal(err)
		}
		n += m
	}
	if string(buf[len(h):]) != "tail" {
		t.Fatal("replay lost bytes")
	}
}

func TestSNI(t *testing.T) {
	a, b := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := b.Read(buf)
		got <- buf[:n]
		b.Close()
	}()
	go tls.Client(a, &tls.Config{ServerName: "matching.np.community.playstation.net", InsecureSkipVerify: true}).Handshake()
	rec := <-got
	if SNI(rec) != "matching.np.community.playstation.net" {
		t.Fatalf("sni %q", SNI(rec))
	}
	if SNI(legacyHello()) != "" || SNI(nil) != "" {
		t.Fatal("legacy hello has no SNI")
	}
}

// The real firmware 4.93 ClientHello, captured from Pier on 2026-11-05 (random zeroed).
func TestClassifyRealFirmwareHello(t *testing.T) {
	h, _ := hex.DecodeString("160303004b0100004703036aecc0f6389656a2301f8c8941f6daf1caa36e41830883068753dab63583f577000010003d003c0035002f000a0005000400ff0100000e000d000a00080401060105010201")
	if len(h) != 80 || Classify(h) != Legacy {
		t.Fatalf("len %d, kind %v", len(h), Classify(h))
	}
	// the same hello with an ECDHE suite or a supported_groups extension is not the firmware
	e := append([]byte(nil), h...)
	e[43+0] = 0xc0
	if Classify(e) != Other {
		t.Fatal("ECDHE suite accepted")
	}
}

// Real D2R (Switch build under Harbor/Ryujinx, 2026-10) game-server hello: only the first 64 bytes were ever logged
// (BsdTap). It shows TLS 1.2 in a 288-byte record, a 32-byte session id and a 284-byte handshake body, none of which
// the 80-byte firmware hello resembles. The tail below is synthetic (typical modern suites and extensions) and
// completes the record to the logged length.
func TestClassifyD2RReplayPrefix(t *testing.T) {
	prefix, _ := hex.DecodeString("16030101200100011C0303E3EC8A6CBB1CF68F0EF30C2D3E3B96B406313D312A4C9B8C81D44EC13781900D205E1E677774F2F15CB72C26F95EBB8707DE6EF84D")
	if len(prefix) != 64 {
		t.Fatal("fixture")
	}
	if Classify(prefix) != Other {
		t.Fatal("a truncated D2R hello must not be the firmware")
	}
	rec := append([]byte(nil), prefix...)
	rec = append(rec, make([]byte, 5+288-len(rec))...)
	// session id (32 bytes) ends at 44+32=76; then suites: ECDHE-RSA-AES128-GCM, ECDHE-RSA-AES256-GCM, CHACHA20, RSA-AES128-GCM
	suites := []byte{0xc0, 0x2f, 0xc0, 0x30, 0xcc, 0xa8, 0x00, 0x9c, 0x00, 0xff}
	p := 44 + 32
	rec[p], rec[p+1] = 0, byte(len(suites))
	copy(rec[p+2:], suites)
	p += 2 + len(suites)
	rec[p], rec[p+1] = 1, 0
	p += 2
	rem := len(rec) - p - 2
	rec[p], rec[p+1] = byte(rem>>8), byte(rem)
	rec[p+2], rec[p+3], rec[p+4], rec[p+5] = 0x00, 0x0a, 0x00, byte(rem-4) // supported_groups
	if Classify(rec) != Other {
		t.Fatal("modern completion classified as firmware")
	}
}

// With the advertised host an IP (real consoles), a modern hello naming the Matching2 hostname still reaches the agent.
func TestHandleAgentNameWithIPHost(t *testing.T) {
	a, b := net.Pipe()
	go tls.Client(a, &tls.Config{ServerName: AgentName, InsecureSkipVerify: true}).Handshake()
	route := make(chan string, 1)
	h := Handlers{AgentHost: "145.241.199.19",
		Legacy: func(c net.Conn) { route <- "legacy"; c.Close() },
		Other:  func(c net.Conn) { route <- "other"; c.Close() }}
	go h.handle(b)
	if r := <-route; r != "legacy" {
		t.Fatalf("routed to %s", r)
	}
	a.Close()
}
