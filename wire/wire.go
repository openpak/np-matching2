// Package wire is the PS3 Matching2 agent protocol as the firmware 4.93 vsh speaks it: a 32-byte header, a
// truncated HMAC-SHA1 MAC and TLV elements. See research/ps3/matching2-protocol.md (private) for the evidence;
// every layout here was observed on a live client or read from the firmware's own parser.
package wire

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
)

const HeaderLen = 32

const (
	KindRequest = 1
	KindReply   = 2
	KindEvent   = 4
)

// Commands seen so far.
const (
	CmdPing        = 0x1001 // plain connection; MAC key = first 16 bytes of the title passphrase
	CmdLogin       = 0x1002 // TLS connection; not MAC'd; carries the passphrase and the NP ticket
	CmdRenew       = 0x1003 // header only; reply carries a fresh 0x5d token
	CmdWorldList   = 0x1008 // header only; GetWorldInfoList
	CmdUnknown1209 = 0x1209 // request: element 0x29 u16 = 1 (server id); reply: 0x20 required token, optional 0x3d, 0x1f, 0x02 list of 0x0a (0x84-byte items), 0x12
)

// Frame is one request, reply or event.
type Frame struct {
	Kind   byte
	Cmd    uint16
	Result byte
	ReqID  [4]byte
	MAC    [16]byte
	Body   []byte // the TLV elements
	Raw    []byte // the whole packet as received
}

var ErrShort = errors.New("wire: short frame")

// Parse reads the first frame of b and returns it with the remaining bytes. A lone 0x00 byte (keepalive) is
// returned as a nil frame.
func Parse(b []byte) (*Frame, []byte, error) {
	if len(b) == 0 {
		return nil, nil, ErrShort
	}
	if b[0] == 0 {
		return nil, b[1:], nil
	}
	if len(b) < HeaderLen {
		return nil, b, ErrShort
	}
	if b[0] != 0x11 {
		return nil, b, errors.New("wire: not a frame")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < HeaderLen || n > len(b) {
		return nil, b, ErrShort
	}
	f := &Frame{Kind: b[1], Cmd: binary.BigEndian.Uint16(b[4:6]), Result: b[6], Body: b[HeaderLen:n], Raw: b[:n]}
	copy(f.ReqID[:], b[8:12])
	copy(f.MAC[:], b[16:32])
	return f, b[n:], nil
}

// Mac is HMAC-SHA1(key, packet with the MAC field zeroed) truncated to 16 bytes.
func Mac(key, pkt []byte) []byte {
	z := append([]byte(nil), pkt...)
	for i := 16; i < 32 && i < len(z); i++ {
		z[i] = 0
	}
	h := hmac.New(sha1.New, key)
	h.Write(z)
	return h.Sum(nil)[:16]
}

// Verify checks the frame's MAC with key.
func (f *Frame) Verify(key []byte) bool { return hmac.Equal(Mac(key, f.Raw), f.MAC[:]) }

// Elements returns the TLVs by id (12 bits).
func (f *Frame) Elements() map[uint16][]byte {
	out := map[uint16][]byte{}
	for p := f.Body; len(p) >= 4; {
		id := binary.BigEndian.Uint16(p) & 0xfff
		n := int(binary.BigEndian.Uint16(p[2:]))
		if 4+n > len(p) {
			break
		}
		out[id] = p[4 : 4+n]
		p = p[4+n:]
	}
	return out
}

// TLV encodes one element; typ is the firmware's type nibble (0 structure, 1 string, 2 binary, 3 u8, 4 u16,
// 5 u32, 6 u64, 7 fixed binary).
func TLV(id, typ uint16, val []byte) []byte {
	b := make([]byte, 4, 4+len(val))
	binary.BigEndian.PutUint16(b, typ<<12|id)
	binary.BigEndian.PutUint16(b[2:], uint16(len(val)))
	return append(b, val...)
}

// Reply builds the reply to req. A nil key leaves the MAC zero (the login reply is not verified).
func Reply(key []byte, cmd uint16, result byte, reqID [4]byte, elems ...[]byte) []byte {
	b := make([]byte, HeaderLen)
	b[0], b[1] = 0x11, KindReply
	binary.BigEndian.PutUint16(b[4:], cmd)
	b[6] = result
	copy(b[8:12], reqID[:])
	for _, e := range elems {
		b = append(b, e...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	if key != nil {
		copy(b[16:32], Mac(key, b))
	}
	return b
}

// Request builds a request (the test client's side).
func Request(key []byte, cmd uint16, reqID [4]byte, elems ...[]byte) []byte {
	b := Reply(key, cmd, 0, reqID, elems...)
	b[1] = KindRequest
	if key != nil {
		for i := 16; i < 32; i++ {
			b[i] = 0
		}
		copy(b[16:32], Mac(key, b))
	}
	return b
}

// World is one SceNpMatching2World as the 0x1008 reply carries it.
type World struct {
	ID          uint16
	Lobbies     uint16
	MaxLobbyMem uint32
	CurLobbyMem uint32
	Rooms       uint16
	RoomMembers uint32
}

// WorldList encodes the 0x02 element of the world list reply.
func WorldList(ws []World) []byte {
	list := []byte{0x00, 0x2a, byte(len(ws) >> 8), byte(len(ws))}
	for _, w := range ws {
		b := make([]byte, 18)
		binary.BigEndian.PutUint16(b[0:], w.ID)
		binary.BigEndian.PutUint16(b[2:], w.Lobbies)
		binary.BigEndian.PutUint32(b[4:], w.MaxLobbyMem)
		binary.BigEndian.PutUint32(b[8:], w.CurLobbyMem)
		binary.BigEndian.PutUint16(b[12:], w.Rooms)
		binary.BigEndian.PutUint32(b[14:], w.RoomMembers)
		list = append(list, TLV(0x2a, 0, b)...)
	}
	return TLV(0x02, 0, list)
}

// Redacted returns a copy of the packet with the values of secret elements (NP ticket 0x11, passphrase 0x15, session key 0x22) overwritten.
func (f *Frame) Redacted() []byte {
	out := append([]byte(nil), f.Raw...)
	for q := out[HeaderLen:]; len(q) >= 4; {
		id := binary.BigEndian.Uint16(q) & 0xfff
		l := int(binary.BigEndian.Uint16(q[2:]))
		if 4+l > len(q) {
			break
		}
		if id == 0x11 || id == 0x15 || id == 0x22 {
			for i := 0; i < l; i++ {
				q[4+i] = 0xAA
			}
		}
		q = q[4+l:]
	}
	return out
}

// All returns every value of a repeated element, in order.
func (f *Frame) All(id uint16) [][]byte {
	var out [][]byte
	for p := f.Body; len(p) >= 4; {
		n := int(binary.BigEndian.Uint16(p[2:]))
		if 4+n > len(p) {
			break
		}
		if binary.BigEndian.Uint16(p)&0xfff == id {
			out = append(out, p[4:4+n])
		}
		p = p[4+n:]
	}
	return out
}

// NpID is the 24-byte element 0x0b: the online id (16 bytes, NUL padded) and 8 option bytes.
func NpID(onlineID string) []byte {
	b := make([]byte, 24)
	copy(b, onlineID)
	copy(b[16:], "ptnpps3")
	return b
}

// UserInfoList encodes the 0x02 element of a 0x1007 reply: one 0x5e entry per user, each holding only its NpId
// (no joined rooms yet).
func UserInfoList(onlineIDs []string) []byte {
	list := []byte{0x00, 0x5e, byte(len(onlineIDs) >> 8), byte(len(onlineIDs))}
	for _, id := range onlineIDs {
		name := make([]byte, 48)
		copy(name, id)
		list = append(list, TLV(0x5e, 0, append(TLV(0x0b, 0, NpID(id)), TLV(0x0c, 1, name)...))...)
	}
	return TLV(0x02, 0, list)
}
