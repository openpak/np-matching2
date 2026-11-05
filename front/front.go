// Package front is the one listener behind Traefik's no-SNI router. The PS3 firmware's Matching2 TLS hello has
// no SNI (80 bytes, 16 suites, no extensions) and cannot be routed by name, and Diablo II Resurrected's game
// server hello has no SNI either. The front reads the first TLS record, tells the two apart by whether the
// hello carries extensions, and hands each its own handling; nothing is decided from anything but the hello.
package front

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"
)

type Kind int

const (
	Other  Kind = iota // anything that is not a legacy firmware hello (D2R, unknown): the old path
	Legacy             // a TLS hello with no extensions at all: the PS3 firmware
)

func (k Kind) String() string {
	if k == Legacy {
		return "legacy"
	}
	return "other"
}

// Classify reads a TLS record holding a ClientHello. It answers Legacy only for the firmware's shape: every cipher
// suite in the old 0x00xx block (RSA/DH key exchange, no ECDHE, no TLS 1.3) and at most the signature_algorithms
// and renegotiation_info extensions. The firmware 4.93 hello is 80 bytes: TLS 1.2, suites 003d 003c 0035 002f 000a
// 0005 0004 00ff, one signature_algorithms extension (captured in Pier, 2026-11-05). A modern client (D2R) offers
// ECDHE suites and several more extensions. Anything malformed is Other.
func Classify(rec []byte) Kind {
	if len(rec) < 9 || rec[0] != 0x16 || rec[5] != 0x01 {
		return Other
	}
	hs := rec[5:]
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+n > len(hs) || n < 35 {
		return Other
	}
	b := hs[4 : 4+n][34:] // after version and random
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return Other
	}
	b = b[1+int(b[0]):] // session id
	if len(b) < 2 {
		return Other
	}
	cs := int(binary.BigEndian.Uint16(b))
	if cs == 0 || cs%2 != 0 || len(b) < 2+cs {
		return Other
	}
	for i := 0; i < cs; i += 2 {
		if b[2+i] != 0x00 {
			return Other
		}
	}
	b = b[2+cs:]
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return Other
	}
	b = b[1+int(b[0]):] // compression methods
	if len(b) == 0 {
		return Legacy
	}
	if len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
		return Other
	}
	ext := b[2:]
	for len(ext) > 0 {
		if len(ext) < 4 {
			return Other
		}
		t, l := binary.BigEndian.Uint16(ext), int(binary.BigEndian.Uint16(ext[2:]))
		if 4+l > len(ext) || (t != 13 && t != 0xff01) {
			return Other
		}
		ext = ext[4+l:]
	}
	return Legacy
}

// SNI returns the server name of a ClientHello record, or "".
func SNI(rec []byte) string {
	if len(rec) < 9 || rec[0] != 0x16 || rec[5] != 0x01 {
		return ""
	}
	hs := rec[5:]
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+n > len(hs) || n < 34 {
		return ""
	}
	b := hs[4+34 : 4+n]
	skip := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		l := int(b[0])
		if lenBytes == 2 {
			l = int(binary.BigEndian.Uint16(b))
		}
		if len(b) < lenBytes+l {
			return false
		}
		b = b[lenBytes+l:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) || len(b) < 2 {
		return ""
	}
	ext := b[2:]
	if int(binary.BigEndian.Uint16(b)) < len(ext) {
		ext = ext[:binary.BigEndian.Uint16(b)]
	}
	for len(ext) >= 4 {
		t, l := binary.BigEndian.Uint16(ext), int(binary.BigEndian.Uint16(ext[2:]))
		if 4+l > len(ext) {
			return ""
		}
		if t == 0 && l >= 5 {
			d := ext[4 : 4+l]
			nl := int(binary.BigEndian.Uint16(d[3:5]))
			if 5+nl <= len(d) {
				return string(d[5 : 5+nl])
			}
		}
		ext = ext[4+l:]
	}
	return ""
}

// Peek reads the first TLS record of c without losing it: it returns the bytes and a conn that replays them.
func Peek(c net.Conn, wait time.Duration) ([]byte, net.Conn, error) {
	c.SetReadDeadline(time.Now().Add(wait))
	defer c.SetReadDeadline(time.Time{})
	r := bufio.NewReaderSize(c, 1<<15)
	h, err := r.Peek(5)
	if err != nil {
		return nil, nil, err
	}
	n := int(binary.BigEndian.Uint16(h[3:5]))
	if h[0] != 0x16 || n == 0 || n > 1<<14 {
		b, _ := r.Peek(r.Buffered())
		return b, &replay{Conn: c, r: r}, nil
	}
	rec, err := r.Peek(5 + n)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), rec...), &replay{Conn: c, r: r}, nil
}

type replay struct {
	net.Conn
	r *bufio.Reader
}

func (p *replay) Read(b []byte) (int, error) { return p.r.Read(b) }

// Handlers are the two destinations.
type Handlers struct {
	Legacy func(net.Conn) // the Matching2 agent's TLS side
	Other  func(net.Conn) // the previous no-SNI behaviour
	Log    *slog.Logger
	// AgentHost is the Matching2 hostname: a hello that names it goes to Legacy whatever it carries.
	AgentHost string
}

// Serve accepts until the listener closes.
func Serve(ln net.Listener, h Handlers) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go h.handle(c)
	}
}

func (h Handlers) handle(c net.Conn) {
	rec, pc, err := Peek(c, 10*time.Second)
	if err != nil {
		c.Close()
		return
	}
	k := Classify(rec)
	if h.AgentHost != "" && SNI(rec) == h.AgentHost {
		k = Legacy
	}
	if h.Log != nil {
		attrs := []any{"kind", k.String(), "hello_bytes", len(rec)}
		if len(rec) <= 128 {
			attrs = append(attrs, "hello", hex.EncodeToString(rec)) // a short hello is the firmware's: nothing secret in it
		}
		h.Log.Debug("no-SNI connection", attrs...)
	}
	if k == Legacy && h.Legacy != nil {
		h.Legacy(pc)
		return
	}
	h.Other(pc)
}

// Terminate returns a handler that ends TLS with cert (TLS 1.2 only, as Traefik's d2gs-tls12 option did) and
// proxies the plaintext to target, like the router it replaces.
func Terminate(certFile, keyFile, target string) (func(net.Conn), error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	return func(c net.Conn) {
		defer c.Close()
		tc := tls.Server(c, cfg)
		tc.SetDeadline(time.Now().Add(15 * time.Second))
		if err := tc.Handshake(); err != nil {
			return
		}
		tc.SetDeadline(time.Time{})
		up, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			return
		}
		defer up.Close()
		done := make(chan struct{}, 2)
		go func() { io.Copy(up, tc); done <- struct{}{} }()
		go func() { io.Copy(tc, up); done <- struct{}{} }()
		<-done
	}, nil
}

var ErrClosed = errors.New("front: closed")
