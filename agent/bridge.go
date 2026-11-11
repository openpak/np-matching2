package agent

// The bridge routes (card openpak/prds#177): common/minecraft's session directory advertises a game a player hosts on another console
// here, as a bridged room owned by the hosting player's NP identity. The host is not connected to this server, so the room is kept for
// them: created under their account, renewed by every PUT (the directory repeats it every 30 s; the core reaps a room 300 s after the
// last renewal), ended by DELETE. It has no room key and belongs to no console connection, so a real console signed in on the same
// account is never touched: its own rooms, room keys and latest-room lookups do not see it.
//
//	GET    /internal/bridge/rooms        the Minecraft rooms real PS3s host: id, room id, owner account, slots, session data (hex)
//	PUT    /internal/bridge/rooms/{game} {host_account, max_slot, external (184 B hex = attrs 0x55+0x56), internal (256 B hex = 0x57+0x58),
//	                                     title, endpoint (optional 4-byte public address of the host's transport)}: answers {id, room_id}
//	DELETE /internal/bridge/rooms/{game} ?title=NPWR05636_00 ends it
//	GET    /internal/bridge/joins        ?after=N the JoinRoom attempts on bridged rooms, in full
//
// Bearer NP_BRIDGE_KEY on all of them.

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"openpak/np-matching2/wire"
)

// BridgeRooms is the part of the matchmaking core the bridged rooms need.
type BridgeRooms interface {
	UpsertBridged(ctx context.Context, title, compat, account, game string, maxSlot uint32, attrs wire.RoomAttrs, memberBin []byte) (*Room, error)
	EndBridged(ctx context.Context, title, game string) error
}

const (
	netVersionPS3 = 0x0884
	extLen        = 184
	intLen        = 256
)

// bridgedAttrs splits the directory's two blobs into the attributes a console host sets: 0x55+0x56 (92 bytes each) and 0x57+0x58 (128 each).
func bridgedAttrs(ext, in []byte) wire.RoomAttrs {
	return wire.RoomAttrs{Bin: map[uint16][]byte{
		wire.AttrExt1: ext[:extLen/2], wire.AttrExt2: ext[extLen/2:],
		wire.AttrInt1: in[:intLen/2], wire.AttrInt2: in[intLen/2:],
		wire.AttrSigOpt: bridgedSigOpt,
	}, Int: map[uint16]uint32{}}
}

// bridgedSigOpt is the signalling option Minecraft 01.84 creates its rooms with (star, hub = owner), so a PS3 joiner signals to the bridge.
var bridgedSigOpt = []byte{2, 0, 0, 0, 0, 0, 0, 0}

// bridgedMemberBin is the host's 0x59 as a console writes it on JoinRoom: the mask of its local players, one player.
var bridgedMemberBin = []byte{0, 0, 0, 1}

// joinEvent is one JoinRoom attempt on a bridged room, as the directory reads it.
type joinEvent struct {
	Seq     int64             `json:"seq"`
	Time    time.Time         `json:"time"`
	Game    string            `json:"game"`
	Kind    string            `json:"kind"`
	Native  string            `json:"native"` // the joiner's online id
	Account string            `json:"account"`
	Data    map[string]string `json:"data,omitempty"`
	Err     string            `json:"err,omitempty"`
}

type joinFeed struct {
	mu  sync.Mutex
	seq int64
	ev  []joinEvent
}

const joinFeedMax = 200

func (f *joinFeed) add(e joinEvent) joinEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	e.Seq, e.Time = f.seq, time.Now().UTC()
	f.ev = append(f.ev, e)
	if over := len(f.ev) - joinFeedMax; over > 0 {
		f.ev = f.ev[over:]
	}
	return e
}

func (f *joinFeed) after(n int64) []joinEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []joinEvent{}
	for _, e := range f.ev {
		if e.Seq > n {
			out = append(out, e)
		}
	}
	return out
}

// recordJoin keeps a JoinRoom attempt on a bridged room and logs it in full: who, the member data and every element of the request
// (secrets redacted), the endpoint the console published, and the verdict.
func (a *Agent) recordJoin(st *conn, f *wire.Frame, r RoomInfo, member RoomMember, endpoint []byte, nat byte, errText string) {
	data := map[string]string{"room": r.ID, "room_id": strconv.FormatUint(r.RoomID, 16), "host": r.Owner, "member_no": strconv.Itoa(int(member.No)),
		"request": hex.EncodeToString(f.Redacted()), "endpoint": hex.EncodeToString(endpoint), "nat": strconv.Itoa(int(nat))}
	if bin, ok := f.MemberAttr(); ok {
		data["member_bin"] = hex.EncodeToString(bin)
	}
	e := a.joins.add(joinEvent{Game: r.Bridge, Kind: "join", Native: st.sess.OnlineID, Account: st.sess.Account, Data: data, Err: errText})
	a.log().Info("matching2 bridged join", "seq", e.Seq, "game", e.Game, "joiner", e.Native, "account", e.Account, "err", errText, "data", e.Data)
}

func bridgeAuthed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := os.Getenv("NP_BRIDGE_KEY")
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if key == "" || !ok || subtle.ConstantTimeCompare([]byte(got), []byte(key)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// minecraftTitle finds the served Minecraft title: by communication id when given, else the one title with the key "minecraft".
func (a *Agent) minecraftTitle(comm string) (Title, bool) {
	if comm != "" {
		t, ok := a.Titles[comm]
		return t, ok && t.Key == "minecraft"
	}
	for _, t := range a.Titles {
		if t.Key == "minecraft" {
			return t, true
		}
	}
	return Title{}, false
}

type bridgedRoomOut struct {
	ID       string `json:"id"`
	RoomID   uint64 `json:"room_id"`
	Owner    string `json:"owner"`
	Max      uint32 `json:"max"`
	External string `json:"external"`
}

// RegisterBridge mounts the bridge routes on the agent's HTTP listener.
func (a *Agent) RegisterBridge(mux *http.ServeMux) {
	mux.HandleFunc("GET /internal/bridge/rooms", bridgeAuthed(a.bridgeList))
	mux.HandleFunc("PUT /internal/bridge/rooms/{game}", bridgeAuthed(a.bridgePut))
	mux.HandleFunc("DELETE /internal/bridge/rooms/{game}", bridgeAuthed(a.bridgeDelete))
	mux.HandleFunc("GET /internal/bridge/joins", bridgeAuthed(func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		json.NewEncoder(w).Encode(a.joins.after(after))
	}))
}

func (a *Agent) bridgeList(w http.ResponseWriter, r *http.Request) {
	t, ok := a.minecraftTitle("")
	if !ok || a.Rooms == nil {
		json.NewEncoder(w).Encode([]bridgedRoomOut{})
		return
	}
	rooms, err := a.Rooms.SearchRooms(r.Context(), t.Key, t.compat(), []string{"np"}, 100, nil)
	if err != nil {
		http.Error(w, "core", http.StatusBadGateway)
		return
	}
	out := []bridgedRoomOut{}
	for _, x := range rooms {
		e1, e2 := x.Attrs.Bin[wire.AttrExt1], x.Attrs.Bin[wire.AttrExt2]
		if x.Bridge != "" || x.Network != "np" || len(e1) != extLen/2 || len(e2) != extLen/2 {
			continue // bridged rooms are other consoles' games; a room without the two external attributes is not a Minecraft 01.84 game
		}
		out = append(out, bridgedRoomOut{ID: x.ID, RoomID: x.RoomID, Owner: x.Owner, Max: x.Max, External: hex.EncodeToString(append(append([]byte{}, e1...), e2...))})
	}
	json.NewEncoder(w).Encode(out)
}

type bridgePutReq struct {
	HostAccount string `json:"host_account"`
	MaxSlot     uint32 `json:"max_slot"`
	External    string `json:"external"`
	Internal    string `json:"internal"`
	Title       string `json:"title"`
	Endpoint    string `json:"endpoint"`
}

func (a *Agent) bridgePut(w http.ResponseWriter, r *http.Request) {
	game := r.PathValue("game")
	var q bridgePutReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&q); err != nil || game == "" || len(game) > 64 || !uuidRe.MatchString(q.HostAccount) || q.MaxSlot < 1 || q.MaxSlot > 64 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ext, err1 := hex.DecodeString(q.External)
	in, err2 := hex.DecodeString(q.Internal)
	if err1 != nil || err2 != nil || len(ext) != extLen || len(in) != intLen || binary.BigEndian.Uint16(ext) != netVersionPS3 {
		http.Error(w, "external: 184 bytes with net version 0x0884; internal: 256 bytes", http.StatusBadRequest)
		return
	}
	t, ok := a.minecraftTitle(q.Title)
	if !ok || a.Bridge == nil || a.Rooms == nil {
		http.Error(w, "no Minecraft title or bridge core", http.StatusServiceUnavailable)
		return
	}
	acct := strings.ToLower(q.HostAccount)
	room, err := a.Bridge.UpsertBridged(r.Context(), t.Key, t.compat(), acct, game, q.MaxSlot, bridgedAttrs(ext, in), bridgedMemberBin)
	if err != nil {
		a.log().Error("matching2 bridged room", "game", game, "err", err)
		http.Error(w, "core", http.StatusBadGateway)
		return
	}
	a.Rooms.Heartbeat(r.Context(), acct) // keeps the host's membership alive; the directory repeats this PUT every 30 s
	if ep, err := hex.DecodeString(q.Endpoint); err == nil && len(ep) == 4 {
		a.Rooms.SetEndpoints(r.Context(), room.ID, acct, ep, 0)
	}
	a.log().Info("matching2 bridged room kept", "game", game, "session", room.ID, "host", acct, "max_slot", q.MaxSlot)
	json.NewEncoder(w).Encode(map[string]any{"id": room.ID, "room_id": room.RoomID})
}

func (a *Agent) bridgeDelete(w http.ResponseWriter, r *http.Request) {
	game := r.PathValue("game")
	t, ok := a.minecraftTitle(r.URL.Query().Get("title"))
	if game == "" || !ok || a.Bridge == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := a.Bridge.EndBridged(r.Context(), t.Key, game); err != nil {
		a.log().Error("matching2 bridged room end", "game", game, "err", err)
		http.Error(w, "core", http.StatusBadGateway)
		return
	}
	a.log().Info("matching2 bridged room ended", "game", game)
	w.Write([]byte("ok\n"))
}
