package front

import (
	"crypto/tls"
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
