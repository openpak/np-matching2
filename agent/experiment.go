package agent

import (
	"context"
	"encoding/binary"
	"sort"
	"sync"
	"time"

	"openpak/np-matching2/wire"
)

// MemberJoined experiment (NP_MATCHING_EVENT_EXPERIMENT=1, prds#145, research matching2-protocol §38). A real PS3 host ignores our 0x320c
// although every check of the vsh 4.93 receive path passes statically. On a join, this sends the event in each unproven variant, one after
// another, expGap apart, and logs each attempt ("matching2 experiment"). Between variants a MemberLeft for the same member goes out on the
// previous variant's connection, so a variant the console did accept does not make the next one a duplicate (0x800223e4). The first host
// request (logged "matching2 experiment: host request") stops the run; the host's RT offer shows in np-community's log. Whichever variant
// was sent last before the reaction is the working one. Remove this file once the answer is known.
const expGap = 5 * time.Second

type experimentState struct {
	mu      sync.Mutex
	account string // host account of the running experiment, "" when none
	reacted bool
}

type expVariant struct {
	name string
	c    *conn
	pkt  []byte
}

// expSaw is called for every request: a non-polling request of the host account while the experiment runs is its reaction.
func (a *Agent) expSaw(account string, connID uint64, cmd uint16) {
	if !a.EventExperiment || account == "" || polling[cmd] {
		return
	}
	a.exp.mu.Lock()
	hit := a.exp.account == account && !a.exp.reacted
	if hit {
		a.exp.reacted = true
	}
	a.exp.mu.Unlock()
	if hit {
		a.log().Info("matching2 experiment: host request", "account", account, "cmd", cmd, "conn", connID)
	}
}

func (a *Agent) runExperiment(ctx context.Context, st *conn, account, session string, key []byte, mi wire.MemberInfo) {
	a.exp.mu.Lock()
	if a.exp.account != "" {
		a.exp.mu.Unlock()
		a.log().Info("matching2 experiment: one already running, join ignored", "account", account, "member", mi.No)
		return
	}
	a.exp.account, a.exp.reacted = account, false
	a.exp.mu.Unlock()
	go func() {
		defer func() {
			a.exp.mu.Lock()
			a.exp.account = ""
			a.exp.mu.Unlock()
		}()
		a.experiment(ctx, st, account, session, key, mi)
	}()
}

// expVariants lists the attempts in order: the plain event on the room's own connection (the static answer, §37), the same bytes on every
// other open connection of the host (most recent room request first: the post-create connection of run 8 that sent 0x320a/0x1207), then on
// the room connection a member element without the optional 0x59/0x6e (and NAT 0), and one carrying the optional 0x3a (the u64 room id, as in the 0x3200/0x1202 bodies).
func (a *Agent) expVariants(st *conn, account, session string, key []byte, mi wire.MemberInfo) []expVariant {
	id := wire.MemberID(mi.No)
	base := wire.Event(key, wire.EventMemberJoined, id, wire.MemberOf(mi))
	vs := []expVariant{{"baseline", st, base}}
	a.msgMu.Lock()
	var others []*conn
	for c, acct := range a.allConns {
		if c != st && acct == account {
			others = append(others, c)
		}
	}
	a.msgMu.Unlock()
	sort.Slice(others, func(i, j int) bool {
		if li, lj := others[i].lastRoom.Load(), others[j].lastRoom.Load(); li != lj {
			return li > lj
		}
		return others[i].id > others[j].id
	})
	for _, c := range others {
		vs = append(vs, expVariant{"other-conn", c, base})
	}
	bare := binary.BigEndian.AppendUint16(nil, id)
	bare = append(bare, make([]byte, 8)...)
	bare = append(bare, 0, 0, 0, 0, 0, 0) // flag attr, nat, team
	nm := make([]byte, 48)
	copy(nm, mi.Name)
	bare = append(bare, wire.TLV(0x0b, 0, wire.NpID(mi.Name, mi.Country))...)
	bare = append(bare, wire.TLV(0x0c, 1, nm)...)
	bare = append(bare, wire.TLV(0x0d, 1, nil)...)
	vs = append(vs, expVariant{"bare-member", st, wire.Event(key, wire.EventMemberJoined, id, wire.TLV(0x4b, 0, bare))})
	rid := binary.BigEndian.AppendUint64(nil, roomIDOf(session))
	vs = append(vs, expVariant{"with-0x3a-room-id", st, wire.Event(key, wire.EventMemberJoined, id, wire.MemberOf(mi), wire.TLV(0x3a, 2, rid))})
	return vs
}

func (a *Agent) experiment(ctx context.Context, st *conn, account, session string, key []byte, mi wire.MemberInfo) {
	vs := a.expVariants(st, account, session, key, mi)
	log := a.log().With("session", session, "account", account, "member", mi.No)
	log.Info("matching2 experiment start", "variants", len(vs), "gap", expGap.String())
	left := wire.MemberLeft(key, wire.MemberID(mi.No), wire.NpID(mi.Name, mi.Country), wire.CauseLeave)
	var prev *conn
	for i, v := range vs {
		if prev != nil {
			if prev.write(left) == nil {
				a.Capture.Event(prev.id, account, wire.EventMemberLeft, "cleanup", left)
				log.Info("matching2 experiment cleanup", "code", "0x320f", "conn", prev.id)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
		err := v.c.write(v.pkt)
		a.Capture.Event(v.c.id, account, wire.EventMemberJoined, v.name, v.pkt)
		log.Info("matching2 experiment", "n", i+1, "variant", v.name, "conn", v.c.id, "bytes", len(v.pkt), "err", err)
		prev = v.c
		select {
		case <-ctx.Done():
			return
		case <-time.After(expGap):
		}
		a.exp.mu.Lock()
		reacted := a.exp.reacted
		a.exp.mu.Unlock()
		if reacted {
			log.Info("matching2 experiment stopped: host reacted", "after_variant", v.name, "conn", v.c.id)
			return
		}
	}
	log.Info("matching2 experiment done: no host request after any variant (check np-community for an RT offer)")
}
