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
	EventMemberJoined   = 0x320c // schema (vsh 0x689410): 0x4b (the new member), 0x3a?, 0x47?, 0x28?; handler 0x2c8968
	EventMemberLeft     = 0x320f // schema (vsh 0x689380): 0x16, 0x0b, 0x62, 0x3a?, 0x28?, 0x47?; handler 0x2c7978
	EventMemberUpdated  = 0x320d // schema: 0x16, 0x06?, 0x1c?, 0x13?, 0x59?, 0x6e?
	EventRoomUpdated    = 0x320e
	EventOwnerChanged   = 0x3212          // schema (vsh 0x689350): 0x16, 0x0b, 0x62, 0x3a?, 0x46?, 0x28?; handler 0x2c7530
	EventRoomDestroyed  = 0x3213          // schema (vsh 0x689338): 0x62, 0x3a?, 0x28?; handler 0x2c7494 tears the room down and raises 0x1104
	EventRoomMessage    = 0x3209          // ROOM_MSG_EVENT_ChatMessage (0x2101): 0x16 source member, 0x44?, 0x1a chat, 0x64?, 0x75
	EventRoomBinary     = 0x320b          // ROOM_MSG_EVENT_Message (0x2102): 0x16 source member, 0x44?, 0x1b message, 0x64? (§24; not signaling)
	EventSignalingPeers = EventRoomBinary // old name, kept for compat: 0x320b is the room Message event
)

// Event builds a kind-4 packet. Header as the firmware reads it (vsh 0x2b4db4 -> 0x2b8940 copies 0x1c bytes after the base four, then
// calls the handler with them, asm 0x2b52f8): code at +4, u32 at +8 (its top nibble picks one listener, 0 = all, vsh 0x2877ec), the room
// handle at +12 (u16, compared with room+10 = head[0..2] of the room data the console got in its 0x3200/0x3201 reply, vsh 0x29bae0), the
// subject member id at +14 (the new member of a MemberJoined, vsh 0x2c896c; the sender of a room message, vsh 0x2c8cbc), MAC at +16 keyed
// with the receiving member's room key (room+0x3f8 = AES-128-ECB decryption of the reply's 0x24 token, vsh 0x29cb6c -> 0x2903a8; the 0x21
// token is only copied to room+0x2fc). The firmware finds that key by the receiving connection (0x29ba04: room+0xa08), so an event is only
// accepted on the connection that sent the room's 0x3200/0x3201. member is the wire id (MemberID).
func Event(key []byte, code, member uint16, elems ...[]byte) []byte {
	b := make([]byte, HeaderLen)
	b[0], b[1] = 0x11, KindEvent
	binary.BigEndian.PutUint16(b[4:], code)
	binary.BigEndian.PutUint16(b[12:], ServerID)
	binary.BigEndian.PutUint16(b[14:], member)
	for _, e := range elems {
		b = append(b, e...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[16:32], Mac(key, b))
	return b
}

// Owner follow-ups. 0x3a is optional in MemberJoined, MemberLeft, OwnerChanged and UpdatedRoomDataInternal and never decides whether the
// event is accepted: each handler raises its API event to the game first (vsh 0x2c8c24 for 0x320c) and only then, when 0x3a is present and
// the receiver is the room owner (room+0xa8 == room+0xac), copies the 0x3a value (up to 0x204 bytes) into an internal request
// (0x289404) that echoes it back as the request's only element: 0x320c -> 0x1203 (request type 0x1a), 0x320f/0x3212 -> 0x1204 (0x1b),
// 0x320e -> 0x120a (0x1c). Internal requests of types 0x1a-0x1c never call the game back (0x290f48), so the follow-up is our only
// proof on hardware that an event got through. We send the u64 room id, as in the 0x3200/0x3201 replies.
func roomIDElem(roomID uint64) []byte {
	return TLV(0x3a, 2, binary.BigEndian.AppendUint64(nil, roomID))
}

// Request types of the owner follow-ups, bits 20-27 of the request id (vsh 0x2b466c builds it as caller<<28 | type<<20 | sequence).
// The 0x1203 a joiner sends as the last step of its own JoinRoom is type 0x0a and must succeed.
const (
	ReqTypeJoinRoom           = 0x0a // JoinRoom: 0x1209 (state 0xe) -> 0x3201 (0xf) -> 0x1203 (0x10); no 0x2001
	ReqTypeMemberJoinedNotice = 0x1a // 0x1203 after a MemberJoined
	ReqTypeMemberLeftNotice   = 0x1b // 0x1204 after a MemberLeft / OwnerChanged
	ReqTypeRoomDataNotice     = 0x1c // 0x120a after an UpdatedRoomDataInternal
)

// ReqType is the request type of a request id.
func ReqType(reqID [4]byte) byte { return byte(binary.BigEndian.Uint32(reqID[:]) >> 20) }

// MemberJoined is the kind-4 MemberJoined event (0x320c) for member mi of room roomID. The handler (vsh 0x2c8968) finds the room by +12,
// requires the id at +14 to be absent and its slot free, builds the member from 0x4b and raises 0x1101; the owner then sends 0x1203.
func MemberJoined(key []byte, roomID uint64, mi MemberInfo) []byte {
	return Event(key, EventMemberJoined, MemberID(mi.No), MemberOf(mi), roomIDElem(roomID))
}

// Event causes: element 0x62, a u8 (vsh element table: size 1, type 3), the SDK's SCE_NP_MATCHING2_EVENT_CAUSE_* values.
const (
	CauseLeave             = 1
	CauseKickout           = 2
	CauseMemberDisappeared = 5
)

// MemberLeft is the kind-4 MemberLeft event (0x320f). The handler (vsh 0x2c7978) finds the room by +12, then looks up the member at +14
// (0x2c79fc) and the member named by 0x16 (0x2c7a1c): both must be in the receiver's member table or the event is dropped. The 0x16 member
// is the one removed; when it is the receiver itself (room+0xa8) the event becomes KickedOut (0x1103) and the room is closed, otherwise
// MemberLeft (0x1102). npid is the leaver's 24-byte NpId (NpID), cause the 0x62 u8.
// MemberLeft (0x2c7c30) then sends the owner's 0x1204 with the 0x3a room id.
func MemberLeft(key []byte, roomID uint64, memberID uint16, npid []byte, cause byte) []byte {
	return Event(key, EventMemberLeft, memberID, TLV(0x16, 4, binary.BigEndian.AppendUint16(nil, memberID)), TLV(0x0b, 0, npid), TLV(0x62, 3, []byte{cause}), roomIDElem(roomID))
}

// OwnerChanged is the kind-4 RoomOwnerChanged event (0x3212). The handler (vsh 0x2c7530) finds the room by +12, requires the member at
// +14 and the one named by 0x16 to exist, and is the only place that moves the owner pointer (room+0xac = the 0x16 member, asm 0x2c75fc)
// before it raises 0x1105. MemberLeft only clears the leaver's slot (0x29ea94), so a migrated room must get this event before the old
// owner's MemberLeft, or every PS3 member keeps an owner pointer to the freed member (the game reads memberList.owner unchecked, §34).
// newOwner is the new owner's wire id (also at +14), npid its NpId; the new owner then sends 0x1204 with the 0x3a room id.
func OwnerChanged(key []byte, roomID uint64, newOwner uint16, npid []byte, cause byte) []byte {
	return Event(key, EventOwnerChanged, newOwner, TLV(0x16, 4, binary.BigEndian.AppendUint16(nil, newOwner)), TLV(0x0b, 0, npid), TLV(0x62, 3, []byte{cause}), roomIDElem(roomID))
}

// RoomDestroyed is the kind-4 RoomDestroyed event (0x3213): the handler (vsh 0x2c7494) finds the room by +12 and tears it down with the
// 0x62 cause (0x29d29c raises 0x1104). No member is looked up, so +14 is 0. It has no owner follow-up, so no 0x3a.
func RoomDestroyed(key []byte, cause byte) []byte {
	return Event(key, EventRoomDestroyed, 0, TLV(0x62, 3, []byte{cause}))
}

// MemberID is the wire member id of room member number no (1-based): slot<<4, slot = no. The firmware indexes its member table by id>>4 at
// room+0xac + slot*4 (vsh 0x29ef9c stores id>>4 at member+10, 0x29ec18 inserts, 0x29e7b0 looks up), and room+0xac (slot 0) is the room
// owner pointer, written before the slot check: a create reply whose own member is id 1 (slot 0) fails its done with 0x800223ff (slot
// taken) at vsh 0x29a378, which is why v0.2.16 hosts never sent 0x1202. Member slots run 1..64 (vsh 0x2984f4). The low nibble goes into
// the room's 2-bit slot map (vsh 0x290128), so it stays 0.
func MemberID(no uint32) uint16 { return uint16(no << 4) }

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
