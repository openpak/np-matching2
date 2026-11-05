// Package agent is the PS3 Matching2 agent: it speaks the firmware's wire (package wire) and holds only protocol
// state (login sessions). Rooms, members and search live in the matchmaking core.
package agent

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
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
	// Worlds counts rooms and members for the world list.
	Worlds(ctx context.Context, title string) (rooms, members uint32, err error)
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
}

func (a *Agent) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

type conn struct {
	comm string
	sess *Session
}

// ServePlain handles the plain TCP connection (0x1001, then the session's requests).
func (a *Agent) ServePlain(c net.Conn) { a.serve(c, false) }

// ServeTLS handles the TLS connection (the 0x1002 login).
func (a *Agent) ServeTLS(c net.Conn) { a.serve(c, true) }

func (a *Agent) serve(c net.Conn, secure bool) {
	defer c.Close()
	st := &conn{}
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
					continue // keepalive
				}
				out := a.handle(context.Background(), st, f)
				if out != nil {
					if _, werr := c.Write(out); werr != nil {
						return
					}
				}
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
	if f.Kind != wire.KindRequest {
		return nil
	}
	el := f.Elements()
	if id := string(el[0x10]); id != "" {
		st.comm = id
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
			log.Info("matching2 bad MAC")
			return nil
		}
		log.Info("matching2 request")
		// element 0x1d = {u16, u8}, stored by the firmware in the agent context; the values are not meaningful so far.
		return wire.Reply(t.Pass[:16], f.Cmd, 0, f.ReqID, wire.TLV(0x1d, 0, []byte{0, 1, 0}))
	case wire.CmdLogin:
		return a.login(ctx, log, t, f, el)
	}
	if f.Cmd == 0x1007 && f.Verify(t.Pass[:16]) {
		// 0x1007 is MAC'd with the passphrase like 0x1001 (the firmware's MAC table): capture it, not implemented yet.
		raw := f.Redacted()
		log.Warn("matching2 unimplemented command", "elements", elementIDs(el), "bytes", len(f.Raw), "hex", hex.EncodeToString(raw), "mac", "passphrase")
		return nil
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
		log.Info("matching2 no session for request")
		st.sess = nil
		return nil
	}
	log = log.With("account", st.sess.Account)
	switch f.Cmd {
	case wire.CmdRenew:
		log.Info("matching2 request")
		a.Store.Extend(ctx, st.sess.ID, SessionTTL)
		return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID, wire.TLV(0x5d, 2, rnd(16)))
	case wire.CmdWorldList:
		log.Info("matching2 request")
		var rooms, members uint32
		if a.Core != nil {
			var err error
			if rooms, members, err = a.Core.Worlds(ctx, t.Key); err != nil {
				log.Error("matching2 core", "err", err)
			}
		}
		w := wire.World{ID: 1, Rooms: uint16(min(rooms, 0xffff)), RoomMembers: members}
		return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID, wire.WorldList([]wire.World{w}))
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
