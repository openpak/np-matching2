// Package agent is the PS3 Matching2 agent: it speaks the firmware's wire (package wire) and holds only protocol
// state (login sessions). Rooms, members and search live in the matchmaking core.
package agent

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"openpak/np-common/ticket"
	"openpak/np-matching2/wire"
)

const SessionTTL = 600 * time.Second

// Title is one game the agent serves.
type Title struct {
	Key  string // the neutral title key in the matchmaking core ("terraria")
	Pass []byte // the 128-byte communication passphrase
}

// Core is what the agent needs from the matchmaking core.
type Core interface {
	// Worlds counts rooms and members for the world list (rooms created from the given networks).
	Worlds(ctx context.Context, title string, networks []string) (rooms, members uint32, err error)
}

// Rooms is the room side of the matchmaking core.
type Rooms interface {
	CreateRoom(ctx context.Context, title, account string, maxSlot uint32, data []byte) (*Room, error)
	LeaveRoom(ctx context.Context, session, account string) error
	SetRoomData(ctx context.Context, session, account string, data []byte) error
	Heartbeat(ctx context.Context, account string)
	SearchRooms(ctx context.Context, title, compat string, networks []string, limit uint32) ([]RoomInfo, error)
	JoinRoom(ctx context.Context, session, account string) (*JoinedRoom, error)
	// SetEndpoints publishes a member's public IPv4 (4 bytes) and NAT type; Members lists a room as a member sees it; Watch streams
	// the core's events for one account until ctx ends.
	SetEndpoints(ctx context.Context, session, account string, addr []byte, nat byte) error
	Members(ctx context.Context, session, viewer string) ([]RoomMember, error)
	Watch(ctx context.Context, account string, fn func(RoomEvent)) error
}

// AccountCore verifies a ticket's account and link (np-common coreclient).
type AccountCore = ticket.AccountCore

type Agent struct {
	Titles  map[string]Title
	Store   *Store
	Tickets *ticket.Signer
	Account AccountCore
	Core    Core
	Log     *slog.Logger
	Stats   Stats
	Capture *Capture
	Rooms   Rooms
	// RoomHost and RoomPort are the room-server endpoint handed to the console in the 0x1209 reply (this agent's plain port).
	RoomHost string
	RoomPort uint16
	// CrossNetworks are the other networks whose rooms of the same compat group a PS3 search lists (NP_MATCHING_CROSS_NETWORKS,
	// e.g. "wiiu"; default none). Listing only: a join into such a room is refused until the cross-network relay exists (prds#145).
	CrossNetworks []string
	// RoomEvents turns on the push of room events (MemberJoined, kind 4) to the members' open connections (NP_MATCHING_ROOM_EVENTS=1).
	// Off by default: the event header layout is inferred from the firmware and not yet seen accepted by a console.
	RoomEvents bool
	// HeartbeatEvery is how often RunHeartbeats refreshes the room members of every console with a live login (default 30 s).
	HeartbeatEvery time.Duration
}

// RunHeartbeats keeps the core membership of every logged-in console fresh until ctx ends. A console's room-server connection
// does not outlive the room creation, and its later traffic (0x1001, 0x1007) is MAC'd with the title passphrase, so it names no
// account: the login session (renewed with 0x1003, SessionTTL) is the signal that the console is still online. Without this the
// core reaped the host after the session ttl (300 s) while it was still hosting (real PS3, 2026-11-06).
func (a *Agent) RunHeartbeats(ctx context.Context) {
	every := a.HeartbeatEvery
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.HeartbeatActive(ctx)
		}
	}
}

// HeartbeatActive heartbeats each account with an unexpired login session once and returns how many accounts it touched.
func (a *Agent) HeartbeatActive(ctx context.Context) int {
	if a.Rooms == nil || a.Store == nil {
		return 0
	}
	seen := map[string]bool{}
	for comm := range a.Titles {
		sessions, err := a.Store.Active(ctx, comm)
		if err != nil {
			a.log().Error("matching2 heartbeat sessions", "err", err)
			continue
		}
		for _, s := range sessions {
			if !seen[s.Account] {
				seen[s.Account] = true
				a.Rooms.Heartbeat(ctx, s.Account)
			}
		}
	}
	return len(seen)
}

// networks is the list of networks whose rooms this agent lists: np first, then the cross-network ones.
func (a *Agent) networks() []string { return append([]string{"np"}, a.CrossNetworks...) }

// onlineID is the name a PS3 shows for a core account: its np online id from the account core, read at the moment it is needed
// (never stored in a room). An account without an np link shows its core display name cut to the 16 characters an NpId holds.
func (a *Agent) onlineID(ctx context.Context, account string) string {
	if a.Account == nil || account == "" {
		return ""
	}
	if l, err := a.Account.GetLinkByAccount(ctx, account); err == nil && l.OnlineID != "" {
		return l.OnlineID
	}
	if acc, err := a.Account.GetAccount(ctx, account); err == nil {
		n := acc.DisplayName
		if len(n) > 16 {
			n = n[:16]
		}
		return n
	}
	return ""
}

func (a *Agent) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

type conn struct {
	comm     string
	sess     *Session
	room     string        // core session id of the room this connection created, joined or named by a room-key MAC
	roomKey  []byte        // that member's room key when the current request was MAC'd with it
	stop     chan struct{} // closed when the connection ends
	w        net.Conn
	secure   bool
	mu       sync.Mutex // serialises writes: replies, keepalive echoes and pushed events
	watching bool
}

func (st *conn) write(b []byte) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	_, err := st.w.Write(b)
	return err
}

// ServePlain handles the plain TCP connection (0x1001, then the session's requests).
func (a *Agent) ServePlain(c net.Conn) { a.serve(c, false) }

// ServeTLS handles the TLS connection (the 0x1002 login).
func (a *Agent) ServeTLS(c net.Conn) { a.serve(c, true) }

func (a *Agent) serve(c net.Conn, secure bool) {
	defer c.Close()
	st := &conn{stop: make(chan struct{}), w: c, secure: secure}
	defer close(st.stop)
	buf := make([]byte, 0x6000)
	for {
		c.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := c.Read(buf)
		if n > 0 {
			rest := buf[:n]
			for len(rest) > 0 {
				f, r, perr := wire.Parse(rest)
				if perr != nil {
					a.log().Info("matching2 bad frame", "err", perr)
					return
				}
				rest = r
				if f == nil {
					// Keepalive. The firmware's receiver also takes a lone 0x00 as one and closes an agent connection about 20 s after
					// the server last sent anything (seen on hardware: the main connection ended 20 s after the last reply while the
					// console kept sending keepalives), so a plain keepalive is answered with one.
					if !secure {
						if st.write([]byte{0}) != nil {
							return
						}
					}
					continue
				}
				out := a.handle(context.Background(), st, f)
				if out != nil {
					if st.write(out) != nil {
						return
					}
				}
				a.watch(st)
			}
		}
		if err != nil {
			if err != io.EOF {
				a.log().Debug("matching2 read", "err", err)
			}
			return
		}
	}
}

func elementIDs(el map[uint16][]byte) []uint16 {
	ids := make([]uint16, 0, len(el))
	for id := range el {
		ids = append(ids, id)
	}
	return ids
}

func rnd(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

// handle answers one request. Every request is logged with its command, title and element ids; never values.
func (a *Agent) handle(ctx context.Context, st *conn, f *wire.Frame) []byte {
	start := time.Now()
	out := a.handle0(ctx, st, f)
	if f.Kind == wire.KindRequest {
		acct := ""
		if st.sess != nil {
			acct = st.sess.Account
		}
		a.Capture.Record(f.Cmd, st.comm, acct, f.Redacted(), out)
		a.Stats.Observe(f.Cmd, out != nil, time.Since(start))
	}
	return out
}

func (a *Agent) handle0(ctx context.Context, st *conn, f *wire.Frame) []byte {
	if f.Kind != wire.KindRequest {
		return nil
	}
	el := f.Elements()
	if id := string(el[0x10]); id != "" {
		st.comm = id
	}
	if st.comm == "" && f.Cmd != wire.CmdLogin {
		// The room-server connection (0x2001 onwards) carries no communication id: find the title and login by the request's session MAC.
		a.resolveSession(ctx, st, f)
	}
	log := a.log().With("cmd", f.Cmd, "title", st.comm)
	t, ok := a.Titles[st.comm]
	if !ok {
		log.Info("matching2 unknown title")
		return nil
	}
	switch f.Cmd {
	case wire.CmdPing:
		if !f.Verify(t.Pass[:16]) {
			if !a.Stats.Quiet(fmt.Sprint("mac", f.Cmd)) {
				log.Info("matching2 bad MAC")
			}
			return nil
		}
		log.Debug("matching2 request")
		// element 0x1d = {u16, u8}, stored by the firmware in the agent context; the values are not meaningful so far.
		return wire.Reply(t.Pass[:16], f.Cmd, 0, f.ReqID, wire.TLV(0x1d, 0, []byte{0, 1, 0}))
	case wire.CmdLogin:
		return a.login(ctx, log, t, f, el)
	}
	if f.Cmd == 0x1007 && f.Verify(t.Pass[:16]) {
		// GetUserInfoList: MAC'd with the passphrase like 0x1001. Elements: 0x0e once per user (online id), 0x05 once per requested
		// info attribute id (u16). The reply lists each user with only its NpId: nobody hosts a room yet.
		var ids []string
		for _, u := range f.All(0x0e) {
			ids = append(ids, string(u))
		}
		log.Debug("matching2 request", "users", len(ids))
		return wire.Reply(t.Pass[:16], f.Cmd, 0, f.ReqID, wire.UserInfoList(ids))
	}
	// Room requests other than create/join (0x3202 leave, ...) are MAC'd with the member's room key, not the session key.
	st.roomKey = nil
	if f.Cmd>>8 == 0x32 && f.Cmd != 0x3200 && f.Cmd != 0x3201 {
		if a.resolveRoomKey(ctx, st, f) {
			log = log.With("account", st.sess.Account)
			return a.roomRequest(ctx, log, st, f)
		}
	}
	// Everything else is MAC'd with the session key of a login.
	if st.sess == nil {
		sessions, err := a.Store.Active(ctx, st.comm)
		if err != nil {
			log.Error("matching2 sessions", "err", err)
			return nil
		}
		for _, s := range sessions {
			if f.Verify(s.Key) {
				st.sess = s
				break
			}
		}
	}
	if st.sess == nil || !f.Verify(st.sess.Key) {
		if !a.Stats.Quiet(fmt.Sprint("nosess", f.Cmd)) {
			log.Info("matching2 no session for request")
		}
		st.sess = nil
		return nil
	}
	log = log.With("account", st.sess.Account)
	switch f.Cmd {
	case wire.CmdRenew:
		log.Debug("matching2 request")
		a.Store.Extend(ctx, st.sess.ID, SessionTTL)
		return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID, wire.TLV(0x5d, 2, rnd(16)))
	case wire.CmdWorldList:
		log.Debug("matching2 request")
		var rooms, members uint32
		if a.Core != nil {
			var err error
			if rooms, members, err = a.Core.Worlds(ctx, t.Key, a.networks()); err != nil {
				log.Error("matching2 core", "err", err)
			}
		}
		w := wire.World{ID: 1, Rooms: uint16(min(rooms, 0xffff)), RoomMembers: members}
		return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID, wire.WorldList([]wire.World{w}))
	}
	if a.Rooms != nil && !a.Stats.Quiet("hb"+st.sess.Account) {
		a.Rooms.Heartbeat(ctx, st.sess.Account)
	}
	switch f.Cmd {
	case 0x3200:
		return a.createRoom(ctx, log, t, st, f)
	case 0x1200, 0x120c:
		return a.searchRooms(ctx, log, t, st, f)
	case 0x3201:
		return a.joinRoom(ctx, log, t, st, f)
	case 0x3202:
		return a.roomRequest(ctx, log, st, f)
	case 0x1202:
		if a.Rooms != nil && st.room == "" {
			st.room = a.latestRoom(ctx, st.sess.Account)
		}
		if a.Rooms != nil && st.room != "" {
			a.Rooms.SetRoomData(ctx, st.room, st.sess.Account, roomBlob(f))
		}
		return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID)
	}
	if f.Cmd == 0x2001 {
		// Second step of the room flow: request carries the login tokens 0x23/0x5d and 0x19 (u8); the reply schema is one element 0x02, the
		// same list of room-server endpoints as in the 0x1209 reply (firmware parser 0x2c20ec). Layout from the parser, not yet seen live.
		log.Info("matching2 command 0x2001 answered", "bytes", len(f.Raw))
		return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID, wire.ServerList(a.RoomHost, a.RoomPort))
	}
	if f.Cmd == wire.CmdUnknown1209 {
		// First room-family command Terraria sends after "Start Game" (request: server id only). The reply schema needs
		// only element 0x20 (a 1..512 byte token); 0x3d is echoed as 1. Meaning of the command is not established.
		if !a.Stats.Quiet("1209") {
			log.Warn("matching2 command 0x1209 answered", "bytes", len(f.Raw), "hex", hex.EncodeToString(f.Redacted()))
		}
		return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID, wire.TLV(0x3d, 4, []byte{0, 1}), wire.TLV(0x20, 2, rnd(16)), wire.ServerList(a.RoomHost, a.RoomPort))
	}
	ids := make([]uint16, 0, len(el))
	for id := range el {
		ids = append(ids, id)
	}
	raw := f.Redacted()
	if len(raw) > 2048 {
		raw = raw[:2048]
	}
	// Capture of a command nobody has implemented yet: the request layout is what the next step needs. Secrets are redacted.
	if a.Stats.Quiet(fmt.Sprint("unimpl", f.Cmd)) {
		return nil
	}
	log.Warn("matching2 unimplemented command", "elements", ids, "bytes", len(f.Raw), "hex", hex.EncodeToString(raw))
	return nil
}

func (a *Agent) login(ctx context.Context, log *slog.Logger, t Title, f *wire.Frame, el map[uint16][]byte) []byte {
	if subtle.ConstantTimeCompare(el[0x15], t.Pass) != 1 {
		log.Info("matching2 login: passphrase mismatch")
		return nil
	}
	id, err := a.Tickets.Verify(el[0x11])
	if err == nil && a.Account != nil {
		id, err = ticket.VerifyAccount(ctx, a.Account, a.Tickets, el[0x11])
	}
	if err != nil {
		log.Info("matching2 login: ticket rejected", "err", err)
		return nil
	}
	s, err := a.Store.Create(ctx, string(el[0x10]), id.AccountID, id.OnlineID, rnd(20), SessionTTL)
	if err != nil {
		log.Error("matching2 login: store", "err", err)
		return nil
	}
	log.Info("matching2 login", "account", id.AccountID, "session", s.ID)
	u32 := make([]byte, 4)
	binary.BigEndian.PutUint32(u32, uint32(s.ID))
	life := binary.BigEndian.AppendUint16(nil, uint16(SessionTTL/time.Second))
	return wire.Reply(nil, f.Cmd, 0, f.ReqID,
		wire.TLV(0x14, 5, u32), wire.TLV(0x22, 2, s.Key), wire.TLV(0x23, 2, rnd(16)), wire.TLV(0x5d, 2, rnd(16)),
		wire.TLV(0x74, 4, life))
}

// roomBlob is the console's room request without the tokens: it is kept in the session data so the unified service (and a later
// SearchRoom) can hand it back; the adapter itself stores nothing.
func roomBlob(f *wire.Frame) []byte {
	var out []byte
	for p := f.Body; len(p) >= 4; {
		id := binary.BigEndian.Uint16(p) & 0xfff
		n := int(binary.BigEndian.Uint16(p[2:]))
		if 4+n > len(p) {
			break
		}
		if id != 0x23 && id != 0x5d && id != 0x20 && id != 0x11 && id != 0x15 && id != 0x22 {
			out = append(out, p[:4+n]...)
		}
		p = p[4+n:]
	}
	if len(out) > 8000 {
		out = out[:8000]
	}
	return out
}

// createRoom answers 0x3200 (CreateJoinRoom, third step): creates the room in the matchmaking core and replies with the five elements the
// firmware requires (tokens, room id, room data, the creator as member 1).
func (a *Agent) createRoom(ctx context.Context, log *slog.Logger, t Title, st *conn, f *wire.Frame) []byte {
	if a.Rooms == nil {
		return nil
	}
	maxSlot := uint32(8)
	if v := f.Elements()[0x3f]; len(v) == 2 {
		if m := uint32(binary.BigEndian.Uint16(v)); m >= 1 && m <= 64 {
			maxSlot = m
		}
	}
	room, err := a.Rooms.CreateRoom(ctx, t.Key, st.sess.Account, maxSlot, roomBlob(f))
	if err != nil {
		log.Error("matching2 create room", "err", err)
		return nil
	}
	st.room = room.ID
	a.keepAlive(st)
	addr, nat := a.publishEndpoint(ctx, log, room.ID, st.sess.Account, f)
	tok, err := a.newRoomKey(ctx, room.ID, st.sess)
	if err != nil {
		log.Error("matching2 room key", "err", err)
		return nil
	}
	log.Info("matching2 room created", "session", room.ID, "max_slot", maxSlot, "bytes", len(f.Raw), "endpoint", len(addr) == 4)
	rd := wire.RoomData{ServerID: 1, WorldID: 1, MaxSlot: uint16(maxSlot)}
	me := wire.MemberInfo{No: room.MemberNo, Name: st.sess.OnlineID, Addr: addr, NAT: nat}
	els := wire.CreateJoinRoomReply(room.RoomID, rd, me, tok, tok)
	return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID, els...)
}

// compatOf is the compatibility group of the searcher: this adapter serves PS3 only, so the group is forced (never taken from the request).
const compatPS3 = "old-gen-1.2.4"

// searchRooms answers SearchRoom (0x1200/0x120c). The request's filters are not decoded yet (INFERRED: it lists every open room of the group);
// the reply is the 0x03 container of RoomDataExternal items (layout from the firmware parser, field meanings inferred).
func (a *Agent) searchRooms(ctx context.Context, log *slog.Logger, t Title, st *conn, f *wire.Frame) []byte {
	if a.Rooms == nil {
		return nil
	}
	rooms, err := a.Rooms.SearchRooms(ctx, t.Key, compatPS3, a.networks(), 20)
	if err != nil {
		log.Error("matching2 search", "err", err)
		return nil
	}
	items := make([]wire.SearchItem, 0, len(rooms))
	foreign := 0
	for _, r := range rooms {
		if r.Network != "np" {
			foreign++
		}
		items = append(items, wire.SearchItem{RoomID: r.RoomID, MaxSlot: uint16(r.Max), Owner: a.onlineID(ctx, r.Owner)})
	}
	log.Info("matching2 search", "rooms", len(items), "cross_network", foreign, "bytes", len(f.Raw))
	return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID, wire.SearchRoomReply(items))
}

// joinRoom answers JoinRoom (0x3201). INFERRED: how the request names the room is not decoded; candidates are u16 elements (0x3e, 0x2e, 0x3d) and an 8-byte 0x3a,
// matched against the room ids of the open rooms; with no match it falls back to the newest open room (logged), so a one-room test works.
func (a *Agent) joinRoom(ctx context.Context, log *slog.Logger, t Title, st *conn, f *wire.Frame) []byte {
	if a.Rooms == nil {
		return nil
	}
	rooms, err := a.Rooms.SearchRooms(ctx, t.Key, compatPS3, a.networks(), 50)
	if err != nil || len(rooms) == 0 {
		log.Warn("matching2 join: no room", "err", err)
		return nil
	}
	want := map[uint16]bool{}
	el := f.Elements()
	for _, id := range []uint16{0x3e, 0x2e, 0x3d} {
		if v := el[id]; len(v) == 2 {
			want[binary.BigEndian.Uint16(v)] = true
		}
	}
	pick, how := rooms[0], "fallback-newest"
	for _, r := range rooms {
		if v := el[0x3a]; len(v) == 8 && binary.BigEndian.Uint64(v) == r.RoomID {
			pick, how = r, "room-id"
			break
		}
		if want[uint16(r.RoomID)] || want[uint16(r.RoomID>>16)] || want[uint16(r.RoomID>>32)] {
			pick, how = r, "u16-match"
			break
		}
	}
	if pick.Network != "np" {
		// Listing only (phase 1): a PS3 cannot reach a Wii U host until the relay terminates both transports (phase 3).
		log.Warn("matching2 join refused: cross-network room, no relay yet", "session", pick.ID, "network", pick.Network, "by", how)
		return nil
	}
	j, err := a.Rooms.JoinRoom(ctx, pick.ID, st.sess.Account)
	if err != nil {
		log.Warn("matching2 join refused", "err", err)
		return nil
	}
	st.room = j.ID
	a.keepAlive(st)
	addr, nat := a.publishEndpoint(ctx, log, j.ID, st.sess.Account, f)
	tok, err := a.newRoomKey(ctx, j.ID, st.sess)
	if err != nil {
		log.Error("matching2 room key", "err", err)
		return nil
	}
	log.Info("matching2 room joined", "session", j.ID, "by", how, "member", j.MemberNo, "endpoint", len(addr) == 4)
	members := make([]wire.MemberInfo, 0, len(j.Members))
	for _, m := range j.Members {
		mi := wire.MemberInfo{No: m.No, Name: st.sess.OnlineID, Addr: m.Addr, NAT: m.NAT}
		if m.Account != st.sess.Account {
			mi.Name = a.onlineID(ctx, m.Account)
		} else if len(addr) == 4 {
			mi.Addr, mi.NAT = addr, nat
		}
		members = append(members, mi)
	}
	rd := wire.RoomData{ServerID: 1, WorldID: 1, MaxSlot: uint16(j.Max)}
	els := wire.JoinRoomReply(uint16(j.MemberNo), j.RoomID, rd, members, tok, tok)
	return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID, els...)
}

// publishEndpoint reads the console's own address from a 0x3200/0x3201 request (0x6e, 4 bytes = its public IPv4; 0x13 = NAT type,
// inferred) and publishes it in the core as the member's "udp" endpoint.
func (a *Agent) publishEndpoint(ctx context.Context, log *slog.Logger, room, account string, f *wire.Frame) ([]byte, byte) {
	el := f.Elements()
	addr := el[0x6e]
	if len(addr) != 4 {
		return nil, 0
	}
	var nat byte
	if v := el[0x13]; len(v) == 1 {
		nat = v[0]
	}
	if err := a.Rooms.SetEndpoints(ctx, room, account, addr, nat); err != nil {
		log.Warn("matching2 endpoint", "err", err)
	}
	return addr, nat
}

// newRoomKey makes and stores the member's room key and returns the reply token that carries it (see wire.RoomKeyToken).
func (a *Agent) newRoomKey(ctx context.Context, room string, sess *Session) ([]byte, error) {
	key := rnd(16)
	if a.Store != nil {
		if err := a.Store.PutRoomKey(ctx, room, sess.Account, key); err != nil {
			return nil, err
		}
	}
	return wire.RoomKeyToken(sess.Key, key)
}

// latestRoom is the room an account most recently created or joined through this agent (a room request on a fresh connection).
func (a *Agent) latestRoom(ctx context.Context, account string) string {
	keys, err := a.Store.RecentRoomKeys(ctx, account)
	if err != nil || len(keys) == 0 {
		return ""
	}
	return keys[0].Room
}

// resolveRoomKey finds the member whose room key MACs this request: the connection's own account first, then every recent key.
// On success the connection holds that member's room, key and login.
func (a *Agent) resolveRoomKey(ctx context.Context, st *conn, f *wire.Frame) bool {
	if a.Store == nil {
		return false
	}
	try := func(account string) bool {
		keys, err := a.Store.RecentRoomKeys(ctx, account)
		if err != nil {
			return false
		}
		for _, k := range keys {
			if !f.Verify(k.Key) {
				continue
			}
			sess := st.sess
			if sess == nil || sess.Account != k.Account {
				if sess, err = a.Store.SessionOf(ctx, st.comm, k.Account); err != nil || sess == nil {
					return false
				}
			}
			st.sess, st.room, st.roomKey = sess, k.Room, k.Key
			return true
		}
		return false
	}
	if st.sess != nil && try(st.sess.Account) {
		return true
	}
	return try("")
}

// roomRequest answers a room request MAC'd with the member's room key (or, from the test client, the session key): the reply is MAC'd
// with the same key.
func (a *Agent) roomRequest(ctx context.Context, log *slog.Logger, st *conn, f *wire.Frame) []byte {
	key := st.sess.Key
	if st.roomKey != nil {
		key = st.roomKey
	}
	if a.Rooms != nil && st.room == "" {
		st.room = a.latestRoom(ctx, st.sess.Account)
	}
	switch f.Cmd {
	case 0x3202:
		if a.Rooms != nil && st.room != "" {
			a.Rooms.LeaveRoom(ctx, st.room, st.sess.Account)
			log.Info("matching2 room left", "session", st.room, "room_key", st.roomKey != nil)
			st.room = ""
		}
		return wire.Reply(key, f.Cmd, 0, f.ReqID)
	}
	if !a.Stats.Quiet(fmt.Sprint("unimpl", f.Cmd)) {
		log.Warn("matching2 unimplemented room command", "elements", elementIDs(f.Elements()), "bytes", len(f.Raw), "hex", hex.EncodeToString(f.Redacted()))
	}
	return nil
}

// watch starts, once per plain connection with a login, the push of room events for that console (when RoomEvents is on).
func (a *Agent) watch(st *conn) {
	if !a.RoomEvents || st.watching || st.secure || st.sess == nil || a.Rooms == nil || a.Store == nil {
		return
	}
	st.watching = true
	account, online := st.sess.Account, st.sess.OnlineID
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-st.stop
		cancel()
	}()
	go func() {
		for ctx.Err() == nil {
			err := a.Rooms.Watch(ctx, account, func(ev RoomEvent) { a.pushEvent(ctx, st, account, online, ev) })
			if ctx.Err() != nil {
				return
			}
			a.log().Warn("matching2 watch", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}

// pushEvent turns a core event for this console into a Matching2 room event. Only MemberJoined (0x320c) is sent: the other events need
// elements not decoded yet (0x62).
func (a *Agent) pushEvent(ctx context.Context, st *conn, account, online string, ev RoomEvent) {
	if ev.Type != "member_joined" || ev.Subject == account || ev.Session == "" {
		return
	}
	log := a.log().With("session", ev.Session, "account", account)
	key, err := a.Store.GetRoomKey(ctx, ev.Session, account)
	if err != nil || key == nil {
		log.Info("matching2 event skipped: no room key for this member", "event", ev.Type)
		return
	}
	members, err := a.Rooms.Members(ctx, ev.Session, account)
	if err != nil {
		log.Warn("matching2 event members", "err", err)
		return
	}
	for _, m := range members {
		if m.Account != ev.Subject {
			continue
		}
		mi := wire.MemberInfo{No: m.No, Name: a.onlineID(ctx, m.Account), Addr: m.Addr, NAT: m.NAT}
		pkt := wire.Event(key, wire.EventMemberJoined, roomIDOf(ev.Session), wire.MemberOf(mi))
		if err := st.write(pkt); err != nil {
			log.Warn("matching2 event write", "err", err)
			return
		}
		log.Info("matching2 event sent", "code", fmt.Sprintf("0x%04x", wire.EventMemberJoined), "member", m.No, "endpoint", len(m.Addr) == 4)
		return
	}
}

func (a *Agent) resolveSession(ctx context.Context, st *conn, f *wire.Frame) {
	for comm := range a.Titles {
		sessions, err := a.Store.Active(ctx, comm)
		if err != nil {
			continue
		}
		for _, s := range sessions {
			if f.Verify(s.Key) {
				st.comm, st.sess = comm, s
				return
			}
		}
	}
}

// keepAlive heartbeats the room member in the core while its room-server connection is open (the console sends only 0x00 keepalives
// on it, which carry no account): without it the core would reap the member after the session ttl.
func (a *Agent) keepAlive(st *conn) {
	if a.Rooms == nil || st.sess == nil {
		return
	}
	account := st.sess.Account
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				a.Rooms.Heartbeat(context.Background(), account)
			case <-st.stop:
				return
			}
		}
	}()
}
