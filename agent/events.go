package agent

import (
	"context"
	"fmt"

	"openpak/np-matching2/wire"
)

// setPushRoom marks the connection as the room's own connection (conn.pushRoom).
func (st *conn) setPushRoom(id string) {
	st.mu.Lock()
	st.pushRoom = id
	st.mu.Unlock()
}

func (st *conn) setOwner(no uint32) {
	st.mu.Lock()
	st.owner = no
	st.mu.Unlock()
}

func (st *conn) ownerNo() uint32 {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.owner
}

// pushOwner sends OwnerChanged (0x3212) when the room's owner in the core is not the one this console knows. It runs on the core's
// owner_changed and, before the MemberLeft, when the leaver is the owner this console knows (the core announces the leave first, the
// console needs the owner moved first: wire.OwnerChanged). leaver is that member's number (0 = none).
func (a *Agent) pushOwner(ctx context.Context, st *conn, account, session string, leaver uint32) {
	log := a.log().With("session", session, "account", account)
	key, err := a.Store.GetRoomKey(ctx, session, account)
	if err != nil || key == nil {
		return
	}
	members, err := a.Rooms.Members(ctx, session, account)
	if err != nil {
		log.Warn("matching2 event members", "err", err)
		return
	}
	owner := ownerOf(members, leaver)
	if owner == nil || owner.No == st.ownerNo() {
		return
	}
	pkt := wire.OwnerChanged(key, roomIDOf(session), wire.MemberID(owner.No), wire.NpID(a.onlineID(ctx, owner.Account), a.country(ctx, owner.Account)), wire.CauseLeave)
	if err := st.write(pkt); err != nil {
		log.Warn("matching2 event write", "err", err)
		return
	}
	st.setOwner(owner.No)
	a.Capture.Event(st.id, account, wire.EventOwnerChanged, "", pkt)
	log.Info("matching2 event sent", "code", fmt.Sprintf("0x%04x", wire.EventOwnerChanged), "owner", owner.No, "conn", st.id)
}

// ownerOf is the room's owner without the leaver, by markOwner's rule: the flagged owner, else the lowest member number.
func ownerOf(members []RoomMember, leaver uint32) *RoomMember {
	var owner *RoomMember
	for i, m := range members {
		if m.No != leaver && (owner == nil || m.Owner && !owner.Owner || m.Owner == owner.Owner && m.No < owner.No) {
			owner = &members[i]
		}
	}
	return owner
}

// carries tells whether room events of session go out on this connection.
func (st *conn) carries(session string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return session != "" && session == st.pushRoom
}

// causeOf maps the core's leave reason to the 0x62 event cause.
func causeOf(reason string) byte {
	switch reason {
	case "leave", "":
		return wire.CauseLeave
	case "kicked":
		return wire.CauseKickout
	}
	return wire.CauseMemberDisappeared // ponytail: ttl reaps and anything else; finer causes when a game cares
}

// pushLeft sends MemberLeft (0x320f) for another member's leave, or RoomDestroyed (0x3213) when the room ended. The leaver's member number
// and account come with the core event (it is no longer in the member list).
func (a *Agent) pushLeft(ctx context.Context, st *conn, account string, ev RoomEvent) {
	log := a.log().With("session", ev.Session, "account", account)
	key, err := a.Store.GetRoomKey(ctx, ev.Session, account)
	if err != nil || key == nil {
		log.Info("matching2 event skipped: no room key for this member", "event", ev.Type)
		return
	}
	cause := causeOf(ev.Text)
	var pkt []byte
	code := uint16(wire.EventRoomDestroyed)
	if ev.Type == "session_ended" {
		pkt = wire.RoomDestroyed(key, cause)
	} else {
		if ev.MemberNo == 0 {
			return
		}
		if ev.MemberNo == st.ownerNo() {
			a.pushOwner(ctx, st, account, ev.Session, ev.MemberNo)
		}
		code = wire.EventMemberLeft
		pkt = wire.MemberLeft(key, roomIDOf(ev.Session), wire.MemberID(ev.MemberNo), wire.NpID(a.onlineID(ctx, ev.Subject), a.country(ctx, ev.Subject)), cause)
	}
	if err := st.write(pkt); err != nil {
		log.Warn("matching2 event write", "err", err)
		return
	}
	a.Capture.Event(st.id, account, code, "", pkt)
	log.Info("matching2 event sent", "code", fmt.Sprintf("0x%04x", code), "member", ev.MemberNo, "cause", cause, "conn", st.id)
}
