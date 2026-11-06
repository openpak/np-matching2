package wire

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

// Room events (kind 4, server push). Codes from the firmware's event table at vsh 0x6c3aa8 and the API event each handler raises
// (vsh 0x2c8968 raises 0x1101 MemberJoined, 0x2c7978 0x1102/0x1103 MemberLeft/KickedOut, 0x2c7530 0x1105 OwnerChanged,
// 0x2c8124 0x1106/0x1108 room data / signaling option, 0x2c85ac 0x1107 member data, 0x2c8e54 0x2101 room message).
const (
	EventMemberJoined   = 0x320c // schema: 0x4b (the new member), 0x3a?, 0x47?, 0x28?
	EventMemberLeft     = 0x320f // schema: 0x16, 0x0b, 0x62, 0x3a?, 0x28?, 0x47? (0x62 not decoded: not sent yet)
	EventMemberUpdated  = 0x320d // schema: 0x16, 0x06?, 0x1c?, 0x13?, 0x59?, 0x6e?
	EventRoomUpdated    = 0x320e
	EventOwnerChanged   = 0x3212
	EventRoomMessage    = 0x3209
	EventSignalingPeers = 0x320b // [I] 0x16, 0x44?, 0x1b, 0x64?: carries an opaque 1..1024-byte blob for a member
)

// Event builds a kind-4 packet. Header as the firmware copies it (vsh 0x2b9e2c, 0x1c bytes after the first four): code at +4, the 64-bit
// room id at +8 (the dispatcher looks the room up by two words from there, vsh 0x28c898; inferred from that lookup), MAC at +16 keyed with
// the receiving member's room key.
func Event(key []byte, code uint16, roomID uint64, elems ...[]byte) []byte {
	b := make([]byte, HeaderLen)
	b[0], b[1] = 0x11, KindEvent
	binary.BigEndian.PutUint16(b[4:], code)
	binary.BigEndian.PutUint64(b[8:], roomID)
	for _, e := range elems {
		b = append(b, e...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[16:32], Mac(key, b))
	return b
}

// RoomKeyToken is the token a 0x3200/0x3201 reply carries in 0x24 and 0x21: the firmware stores the room key as the AES-128-ECB
// decryption of that token with the first 16 bytes of the login session key (vsh 0x2903a8, key from grp+0x90), keeping the token's
// length. Both tokens carry it because which one the firmware uses is not settled (the code copies one into the room at +0x3f8).
func RoomKeyToken(sessionKey, roomKey []byte) ([]byte, error) {
	if len(sessionKey) < 16 || len(roomKey) == 0 || len(roomKey)%16 != 0 {
		return nil, errors.New("wire: room key token needs a 16-byte session key and a 16-byte multiple room key")
	}
	c, err := aes.NewCipher(sessionKey[:16])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(roomKey))
	for i := 0; i < len(roomKey); i += 16 {
		c.Encrypt(out[i:i+16], roomKey[i:i+16])
	}
	return out, nil
}

// RoomKeyFromToken is what the firmware does with the token (the test client uses it).
func RoomKeyFromToken(sessionKey, token []byte) ([]byte, error) {
	if len(sessionKey) < 16 || len(token) == 0 || len(token)%16 != 0 {
		return nil, errors.New("wire: bad room key token")
	}
	c, err := aes.NewCipher(sessionKey[:16])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(token))
	for i := 0; i < len(token); i += 16 {
		c.Decrypt(out[i:i+16], token[i:i+16])
	}
	return out, nil
}
