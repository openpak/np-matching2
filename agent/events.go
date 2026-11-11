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
		code = wire.EventMemberLeft
		pkt = wire.MemberLeft(key, wire.MemberID(ev.MemberNo), wire.NpID(a.onlineID(ctx, ev.Subject), a.country(ctx, ev.Subject)), cause)
	}
	if err := st.write(pkt); err != nil {
		log.Warn("matching2 event write", "err", err)
		return
	}
	a.Capture.Event(st.id, account, code, "", pkt)
	log.Info("matching2 event sent", "code", fmt.Sprintf("0x%04x", code), "member", ev.MemberNo, "cause", cause, "conn", st.id)
}
