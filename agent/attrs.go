package agent

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"

	"openpak/np-matching2/wire"
)

// This file serves the attribute side of Matching2 (Minecraft PS3 01.84, research minecraft-lce/ps3-0184-vs-wiiu-2026-11-10.md): the two
// internal bin attrs 0x57/0x58, the two external bin attrs 0x55/0x56, the searchable ints 0x4c-0x53, each member's 0x59, and the commands that
// set and read them. Request layouts come from the firmware's builders (vsh 0x2b9628, 0x2b9ca0, 0x2b9d60, 0x2b9754; matching2-protocol.md §6),
// not from a live capture: the first request of each of these commands is logged at WARN with its hex so the first real console shows them.
// Every value is stored in the matchmaking core (room attrs, member data), never in this process.

// roomData is the 0x71 data for a room, with the host's signalling option (0x6d) echoed. A room with no internal attrs (Terraria) keeps the
// verified attr bytes; otherwise the two attrs come back as the host set them, last written by `last` (the owner's wire member id).
func roomData(attrs wire.RoomAttrs, maxSlot, last uint16) wire.RoomData {
	rd := wire.RoomData{WorldID: 1, MaxSlot: maxSlot, Flags: attrs.Bin[wire.AttrSigOpt]}
	a1, ok1 := attrs.Bin[wire.AttrInt1]
	a2, ok2 := attrs.Bin[wire.AttrInt2]
	if ok1 || ok2 {
		rd.Attr1, rd.Attr2, rd.LastMember = a1, a2, last
	}
	return rd
}

func binSizes(a wire.RoomAttrs) map[string]int {
	out := map[string]int{}
	for id, v := range a.Bin {
		out[fmt.Sprintf("0x%02x", id)] = len(v)
	}
	return out
}

func ownerNo(ms []wire.MemberInfo) uint32 {
	for _, m := range ms {
		if m.Owner {
			return m.No
		}
	}
	return 1
}

// seen logs the first request of a command whose layout is decoded from the firmware but not yet seen live, at WARN with the redacted hex.
func (a *Agent) seen(log *slog.Logger, f *wire.Frame) {
	if a.Stats.Quiet(fmt.Sprint("seen", f.Cmd)) {
		return
	}
	raw := f.Redacted()
	if len(raw) > 2048 {
		raw = raw[:2048]
	}
	log.Warn("matching2 statically decoded command, first sight", "elements", elementIDs(f.Elements()), "bytes", len(f.Raw), "hex", hex.EncodeToString(raw))
}

// roomOf is the room a request on this connection concerns: the connection's own, else the account's newest.
func (a *Agent) roomOf(ctx context.Context, st *conn) string {
	if a.Rooms != nil && st.room == "" && st.sess != nil {
		st.room = a.latestRoom(ctx, st.sess.Account)
	}
	return st.room
}

// storeAttrs merges the attributes a 0x1202 request carries into the room (the external bins and ints of CreateJoinRoom).
func (a *Agent) storeAttrs(ctx context.Context, log *slog.Logger, st *conn, f *wire.Frame) {
	attrs := f.RoomAttrs()
	if attrs.Empty() {
		return
	}
	if err := a.Rooms.SetRoomAttrs(ctx, st.room, st.sess.Account, attrs); err != nil {
		log.Warn("matching2 room attrs refused", "err", err)
		return
	}
	log.Info("matching2 room attrs stored", "cmd", f.Cmd, "bins", binSizes(attrs), "ints", attrs.Int)
}

// setExternal answers SetRoomDataExternal (0x1207): the external bins and searchable ints, merged into the room. The reply has no element.
func (a *Agent) setExternal(ctx context.Context, log *slog.Logger, st *conn, f *wire.Frame) []byte {
	a.seen(log, f)
	if a.Rooms != nil && a.roomOf(ctx, st) != "" {
		a.storeAttrs(ctx, log, st, f)
	}
	return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID)
}

// roomMatches matches the u16 a request names a room by (0x3d, 0x3e, 0x2e) against a room id: the firmware sends one 16-bit part of it
// (the low part in the Terraria join, §21), so all three parts are accepted.
func roomMatches(roomID uint64, parts [][]byte) bool {
	for _, p := range parts {
		if len(p) != 2 {
			continue
		}
		v := binary.BigEndian.Uint16(p)
		if v == uint16(roomID) || v == uint16(roomID>>16) || v == uint16(roomID>>32) {
			return true
		}
	}
	return false
}

// roomDataExternalList answers GetRoomDataExternalList (0x1208): one 0x3d per requested room, one 0x05 per requested attribute id; the reply
// is the list of RoomDataExternal items (the SearchRoom item) carrying those attributes.
func (a *Agent) roomDataExternalList(ctx context.Context, log *slog.Logger, t Title, st *conn, f *wire.Frame) []byte {
	if a.Rooms == nil {
		return nil
	}
	a.seen(log, f)
	rooms, err := a.Rooms.SearchRooms(ctx, t.Key, t.compat(), a.networks(), 50, nil)
	if err != nil {
		log.Error("matching2 external list", "err", err)
		return nil
	}
	// The firmware sends each requested attribute id as (type nibble << 12 | id): the game's 0x55/0x56 arrive as 0x2055/0x2056, and the
	// library adds the owner info it parses itself, 0x000b, 0x100c, 0x100d (NpId, name, avatar) and 0x206c (the host's external info).
	// Matching on the raw value found none of the host's attributes, so the reply had no external bins, the game's check (exactly two,
	// vsh item -> game list+0x54, EB 0xc96560 event 5) failed and the join silently went back to the list (2026-11-13 16:02Z).
	want := map[uint16]bool{}
	for _, v := range f.All(0x05) {
		if len(v) == 2 {
			want[binary.BigEndian.Uint16(v)&0xfff] = true
		}
	}
	ids := f.All(0x3d)
	var items []wire.SearchItem
	for _, r := range rooms {
		if !roomMatches(r.RoomID, ids) {
			continue
		}
		attrs := wire.RoomAttrs{Bin: map[uint16][]byte{}, Int: map[uint16]uint32{}}
		for id, v := range r.Attrs.Bin {
			if (id == wire.AttrExt1 || id == wire.AttrExt2 || id == wire.AttrExtra) && (len(want) == 0 || want[id]) {
				attrs.Bin[id] = v
			}
		}
		for id, v := range r.Attrs.Int {
			if len(want) == 0 || want[id] {
				attrs.Int[id] = v
			}
		}
		owner, country := a.onlineID(ctx, r.Owner), a.country(ctx, r.Owner)
		it := wire.SearchItem{RoomID: r.RoomID, MaxSlot: uint16(r.Max), Owner: owner, OwnerCountry: country, Attrs: attrs}
		if want[0x0b] {
			it.Extra = append(it.Extra, wire.TLV(0x0b, 0, wire.NpID(owner, country))...)
		}
		if want[0x0c] {
			name := make([]byte, 48)
			copy(name, owner)
			it.Extra = append(it.Extra, wire.TLV(0x0c, 1, name)...)
		}
		if want[0x0d] {
			it.Extra = append(it.Extra, wire.TLV(0x0d, 1, nil)...)
		}
		items = append(items, it)
	}
	log.Info("matching2 external list", "requested", len(ids), "rooms", len(items), "attr_ids", len(want))
	return wire.Reply(st.sess.Key, f.Cmd, 0, f.ReqID, wire.RoomDataExternalList(items))
}

// memberAccount finds the account of the member a request names by its wire id (slot << 4, element 0x16); ok is false when the room does not
// list it.
func memberAccount(j *JoinedRoom, id uint16) (RoomMember, bool) {
	for _, m := range j.Members {
		if wire.MemberID(m.No) == id {
			return m, true
		}
	}
	return RoomMember{}, false
}

func requestedMember(f *wire.Frame) (uint16, bool) {
	v := f.Elements()[0x16]
	if len(v) != 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(v), true
}

// setRoomInternal answers SetRoomDataInternal (0x3204): the owner's new 0x57/0x58, stored in the core (which tells the other members; the
// agent pushes the update event). The reply is the required 0x70.
func (a *Agent) setRoomInternal(ctx context.Context, log *slog.Logger, st *conn, f *wire.Frame, key []byte) []byte {
	a.seen(log, f)
	attrs := f.RoomAttrs()
	if a.Rooms != nil && st.room != "" && !attrs.Empty() {
		if err := a.Rooms.SetRoomAttrs(ctx, st.room, st.sess.Account, attrs); err != nil {
			log.Warn("matching2 room data internal refused", "err", err)
		}
	}
	log.Info("matching2 room data internal set", "bins", binSizes(attrs))
	return wire.Reply(key, f.Cmd, 0, f.ReqID, wire.SetRoomDataInternalReply()...)
}

// setMemberData answers SetRoomMemberDataInternal (0x3206): a member's new 0x59 (the local-player mask). The member is the one named by 0x16.
func (a *Agent) setMemberData(ctx context.Context, log *slog.Logger, st *conn, f *wire.Frame, key []byte) []byte {
	a.seen(log, f)
	if a.Rooms == nil || st.room == "" {
		return nil
	}
	target := st.sess.Account
	if id, ok := requestedMember(f); ok {
		j, err := a.Rooms.GetRoom(ctx, st.room, st.sess.Account)
		if err != nil {
			log.Warn("matching2 member data: room", "err", err)
			return nil
		}
		m, ok := memberAccount(j, id)
		if !ok {
			log.Warn("matching2 member data: no such member", "id", id)
			return nil
		}
		target = m.Account
	}
	bin, ok := f.MemberAttr()
	if ok {
		if err := a.Rooms.SetMemberBin(ctx, st.room, st.sess.Account, target, bin); err != nil {
			log.Warn("matching2 member data refused", "err", err)
		}
	}
	log.Info("matching2 member data set", "self", target == st.sess.Account, "has_bin", ok, "bin", len(bin))
	return wire.Reply(key, f.Cmd, 0, f.ReqID)
}

// getMemberData answers GetRoomMemberDataInternal (0x3207): the named member as a 0x4b element, its 0x59 included.
func (a *Agent) getMemberData(ctx context.Context, log *slog.Logger, st *conn, f *wire.Frame, key []byte) []byte {
	a.seen(log, f)
	id, ok := requestedMember(f)
	if !ok || a.Rooms == nil || st.room == "" {
		log.Warn("matching2 member data read without a member or room", "has_id", ok)
		return nil
	}
	j, err := a.Rooms.GetRoom(ctx, st.room, st.sess.Account)
	if err != nil {
		log.Warn("matching2 member data read: room", "err", err)
		return nil
	}
	m, ok := memberAccount(j, id)
	if !ok {
		log.Warn("matching2 member data read: no such member", "id", id)
		return nil
	}
	mi := wire.MemberInfo{No: m.No, Name: a.onlineID(ctx, m.Account), Country: a.country(ctx, m.Account), Addr: m.Addr, NAT: m.NAT, Owner: m.Owner, Bin: m.Bin}
	log.Info("matching2 member data read", "member", m.No, "bin", len(m.Bin))
	return wire.Reply(key, f.Cmd, 0, f.ReqID, wire.MemberOf(mi))
}

// kickout answers KickoutRoomMember (0x3211): the owner removes the member named by 0x16 (0x17 = block flag, 0x28 = option data, not used).
func (a *Agent) kickout(ctx context.Context, log *slog.Logger, st *conn, f *wire.Frame, key []byte) []byte {
	a.seen(log, f)
	id, ok := requestedMember(f)
	if !ok || a.Rooms == nil || st.room == "" {
		return nil
	}
	j, err := a.Rooms.GetRoom(ctx, st.room, st.sess.Account)
	if err != nil {
		log.Warn("matching2 kickout: room", "err", err)
		return nil
	}
	m, ok := memberAccount(j, id)
	if !ok {
		log.Warn("matching2 kickout: no such member", "id", id)
		return nil
	}
	if err := a.Rooms.KickMember(ctx, st.room, st.sess.Account, m.Account); err != nil {
		log.Warn("matching2 kickout refused", "err", err)
	} else {
		log.Info("matching2 member kicked", "member", m.No)
	}
	return wire.Reply(key, f.Cmd, 0, f.ReqID)
}

// pushRoomData sends UpdatedRoomDataInternal (0x320e) to a member after another member changed the room: the two internal bins as stored.
func (a *Agent) pushRoomData(ctx context.Context, st *conn, account string, ev RoomEvent) {
	log := a.log().With("session", ev.Session, "account", account)
	key, err := a.Store.GetRoomKey(ctx, ev.Session, account)
	if err != nil || key == nil {
		return
	}
	j, err := a.Rooms.GetRoom(ctx, ev.Session, account)
	if err != nil {
		log.Warn("matching2 event room", "err", err)
		return
	}
	a1, ok1 := j.Attrs.Bin[wire.AttrInt1]
	a2, ok2 := j.Attrs.Bin[wire.AttrInt2]
	if !ok1 && !ok2 {
		return
	}
	var last uint16
	if m, ok := memberByAccount(j, ev.Subject); ok {
		last = wire.MemberID(m.No)
	}
	if err := st.write(wire.RoomDataUpdated(key, roomIDOf(ev.Session), last, a1, a2)); err != nil {
		log.Warn("matching2 event write", "err", err)
		return
	}
	log.Info("matching2 event sent", "code", fmt.Sprintf("0x%04x", wire.EventRoomUpdated), "by", last, "bytes", len(a1)+len(a2))
}

// pushMemberData sends UpdatedRoomMemberDataInternal (0x320d) to a member after another member's 0x59 changed.
func (a *Agent) pushMemberData(ctx context.Context, st *conn, account string, ev RoomEvent) {
	log := a.log().With("session", ev.Session, "account", account)
	key, err := a.Store.GetRoomKey(ctx, ev.Session, account)
	if err != nil || key == nil {
		return
	}
	j, err := a.Rooms.GetRoom(ctx, ev.Session, account)
	if err != nil {
		log.Warn("matching2 event room", "err", err)
		return
	}
	m, ok := memberByAccount(j, ev.Subject)
	if !ok || len(m.Bin) == 0 {
		return
	}
	if err := st.write(wire.MemberDataUpdated(key, wire.MemberID(m.No), m.Bin)); err != nil {
		log.Warn("matching2 event write", "err", err)
		return
	}
	log.Info("matching2 event sent", "code", fmt.Sprintf("0x%04x", wire.EventMemberUpdated), "member", m.No, "bin", len(m.Bin))
}

func memberByAccount(j *JoinedRoom, account string) (RoomMember, bool) {
	for _, m := range j.Members {
		if m.Account == account {
			return m, true
		}
	}
	return RoomMember{}, false
}
