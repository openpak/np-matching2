// Package client is a headless Matching2 client: it speaks the firmware's wire from the console side, so the agent
// can be exercised without an emulator. It mirrors what vsh sends (research/ps3/matching2-protocol.md).
package client

import (
	"errors"
	"net"
	"time"

	"openpak/np-matching2/wire"
)

type Client struct {
	Comm       string
	Pass       []byte // the 128-byte title passphrase
	Plain, TLS net.Conn
	Key        []byte // the session key from the login
	seq        uint32
}

func (c *Client) id() [4]byte {
	c.seq++
	v := 0x10100000 + c.seq
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func roundTrip(conn net.Conn, req []byte) (*wire.Frame, error) {
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	return ReadFrame(conn)
}

// ReadFrame reads the next frame, skipping the server's lone 0x00 keepalive bytes.
func ReadFrame(conn net.Conn) (*wire.Frame, error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 0x6000)
	var have []byte
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		have = append(have, buf[:n]...)
		for len(have) > 0 && have[0] == 0 {
			have = have[1:]
		}
		if len(have) < 4 {
			continue
		}
		f, _, err := wire.Parse(have)
		if err != nil {
			continue // a frame split over reads
		}
		if f == nil {
			return nil, errors.New("client: no reply frame")
		}
		return f, nil
	}
}

// Ping is 0x1001 on the plain connection, MAC'd with the passphrase.
func (c *Client) Ping() (*wire.Frame, error) {
	c.Plain.Write([]byte{0}) // the firmware opens with a keepalive byte
	f, err := roundTrip(c.Plain, wire.Request(c.Pass[:16], wire.CmdPing, c.id(), wire.TLV(0x10, 1, []byte(c.Comm)), wire.TLV(0x73, 4, []byte{0, 1})))
	if err != nil {
		return nil, err
	}
	if !f.Verify(c.Pass[:16]) {
		return nil, errors.New("client: ping reply MAC")
	}
	return f, nil
}

// Login is 0x1002 on the TLS connection (no MAC); it stores the session key.
func (c *Client) Login(ticket []byte, onlineID, name string) (*wire.Frame, error) {
	npid := make([]byte, 24)
	copy(npid, onlineID)
	copy(npid[16:], "ptnpps3")
	nm := make([]byte, 48)
	copy(nm, name)
	req := wire.Request(nil, wire.CmdLogin, c.id(),
		wire.TLV(0x0f, 1, []byte("np")), wire.TLV(0x10, 1, []byte(c.Comm)), wire.TLV(0x73, 4, []byte{0, 1}),
		wire.TLV(0x0b, 0, npid), wire.TLV(0x0c, 1, nm), wire.TLV(0x0d, 1, []byte("http://avatar.invalid/a.png")),
		wire.TLV(0x15, 2, c.Pass), wire.TLV(0x11, 2, ticket), wire.TLV(0x6f, 2, make([]byte, 16)))
	f, err := roundTrip(c.TLS, req)
	if err != nil {
		return nil, err
	}
	if f.Result != 0 {
		return f, errors.New("client: login refused")
	}
	c.Key = f.Elements()[0x22]
	return f, nil
}

// Call sends a header-only request on the plain connection, MAC'd with the session key.
// CallKey sends a request MAC'd with key (a room key) and checks the reply against it.
func (c *Client) CallKey(key []byte, cmd uint16, elems ...[]byte) (*wire.Frame, error) {
	f, err := roundTrip(c.Plain, wire.Request(key, cmd, c.id(), elems...))
	if err != nil {
		return nil, err
	}
	if !f.Verify(key) {
		return nil, errors.New("client: reply MAC")
	}
	return f, nil
}

func (c *Client) Call(cmd uint16, elems ...[]byte) (*wire.Frame, error) {
	f, err := roundTrip(c.Plain, wire.Request(c.Key, cmd, c.id(), elems...))
	if err != nil {
		return nil, err
	}
	if !f.Verify(c.Key) {
		return nil, errors.New("client: reply MAC")
	}
	return f, nil
}
