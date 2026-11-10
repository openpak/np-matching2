package agent

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/openpak/matchmaking/proto/openpak/matchmaking/v1"
	"openpak/np-matching2/wire"
)

// MatchmakingCore is the gRPC client of the matchmaking core.
type MatchmakingCore struct {
	C   pb.MatchmakingClient
	Key string
}

func DialMatchmaking(addr, key string) (*MatchmakingCore, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return &MatchmakingCore{C: pb.NewMatchmakingClient(conn), Key: key}, conn, nil
}

func (m *MatchmakingCore) ctx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "x-internal-key", m.Key)
}

// Worlds counts the open and closed rooms of a title created from the given networks, and their members.
func (m *MatchmakingCore) Worlds(ctx context.Context, title string, networks []string) (uint32, uint32, error) {
	res, err := m.C.SearchSessions(m.ctx(ctx), &pb.SearchSessionsRequest{Title: &pb.TitleRef{Network: "np", Title: title}, Networks: networks, IncludeClosed: true, Limit: 100})
	if err != nil {
		return 0, 0, err
	}
	var members uint32
	for _, s := range res.GetSessions() {
		for _, a := range s.GetAttrs() {
			if a.GetName() == "$members" {
				members += uint32(a.GetIntValue())
			}
		}
	}
	return res.GetHits(), members, nil
}

// Room is a core session as the agent needs it.
type Room struct {
	ID       string
	RoomID   uint64 // the first 8 bytes of the session id, the room id the console sees
	MemberNo uint32
}

// roomIDOf is the 64-bit room id the console sees. The firmware builds it as serverId<<48 | a<<32 | b<<16 | c from three u16 on the wire
// (inferred from the search-result parser, vsh 0x2bd548), so the id is server 1 plus the first 48 bits of the session id.
func roomIDOf(session string) uint64 {
	b, err := hex.DecodeString(strings.ReplaceAll(session, "-", ""))
	if err != nil || len(b) < 8 {
		return 0
	}
	return 1<<48 | binary.BigEndian.Uint64(append([]byte{0, 0}, b[:6]...))
}

// roomAttrs are the searchable attributes of a PS3 room: the compat group and the console. Never a name or any other identity:
// names are resolved from the account core when a room is read (owner rule, prds#145).
func roomAttrs(compat string) []*pb.Attr {
	return []*pb.Attr{
		{Name: "compat", Type: pb.AttrType_ATTR_TYPE_STRING, StringValue: compat, Searchable: true},
		{Name: "console", Type: pb.AttrType_ATTR_TYPE_STRING, StringValue: "ps3", Searchable: true},
	}
}

// attrsToPB stores the attributes a console set on a room as core session attrs: bins "b55".."b58" (bytes), ints "i4c".."i53". The ints and
// the external bins (0x55, 0x56) are marked searchable because the core shows a non-member only searchable attrs: SearchRoom filters run on the
// ints, and a joiner reads the external bins (GetRoomDataExternalList) before it is a member. The internal bins (0x57, 0x58) are members-only.
// They live in the core's database with the session, so they survive an agent restart.
func attrsToPB(a wire.RoomAttrs) []*pb.Attr {
	var out []*pb.Attr
	for id, v := range a.Bin {
		out = append(out, &pb.Attr{Name: fmt.Sprintf("b%02x", id), Type: pb.AttrType_ATTR_TYPE_BYTES, BytesValue: v, Searchable: id == wire.AttrExt1 || id == wire.AttrExt2})
	}
	for id, v := range a.Int {
		out = append(out, &pb.Attr{Name: fmt.Sprintf("i%02x", id), Type: pb.AttrType_ATTR_TYPE_INT, IntValue: int64(v), Searchable: true})
	}
	return out
}

// attrsFromPB is the inverse of attrsToPB; attrs of other names (compat, console, $members) are skipped.
func attrsFromPB(as []*pb.Attr) wire.RoomAttrs {
	a := wire.RoomAttrs{Bin: map[uint16][]byte{}, Int: map[uint16]uint32{}}
	for _, x := range as {
		var id uint16
		switch {
		case len(x.GetName()) == 3 && x.GetName()[0] == 'b':
			if _, err := fmt.Sscanf(x.GetName()[1:], "%02x", &id); err == nil {
				a.Bin[id] = x.GetBytesValue()
			}
		case len(x.GetName()) == 3 && x.GetName()[0] == 'i':
			if _, err := fmt.Sscanf(x.GetName()[1:], "%02x", &id); err == nil {
				a.Int[id] = uint32(x.GetIntValue())
			}
		}
	}
	return a
}

// filterOps maps SceNpMatching2Operator (SDK order, inferred) to the core's operators.
var filterOps = map[uint32]string{1: "eq", 2: "ne", 3: "lt", 4: "le", 5: "gt", 6: "ge"}

// CreateRoom opens a Terraria room for the account: kind room under the neutral title key, attributes for the unified service
// (compat group and console), the console's own request kept in the data blob. No display name goes to the core.
func (m *MatchmakingCore) CreateRoom(ctx context.Context, title, compat, account string, maxSlot uint32, data []byte, attrs wire.RoomAttrs, memberBin []byte) (*Room, error) {
	res, err := m.C.CreateSession(m.ctx(ctx), &pb.CreateSessionRequest{
		Title: &pb.TitleRef{Network: "np", Title: title}, Creator: account, Network: "np", Kind: "room",
		MaxMembers: maxSlot, MigrateOwner: true, TtlSeconds: 300, Data: data, Attrs: append(roomAttrs(compat), attrsToPB(attrs)...), MemberData: memberBin,
	})
	if err != nil {
		return nil, err
	}
	id := res.GetSession().GetId()
	return &Room{ID: id, RoomID: roomIDOf(id), MemberNo: res.GetMemberNo()}, nil
}

func (m *MatchmakingCore) LeaveRoom(ctx context.Context, session, account string) error {
	_, err := m.C.LeaveSession(m.ctx(ctx), &pb.LeaveSessionRequest{SessionId: session, AccountId: account, Reason: "leave"})
	return err
}

func (m *MatchmakingCore) SetRoomData(ctx context.Context, session, account string, data []byte) error {
	_, err := m.C.UpdateSession(m.ctx(ctx), &pb.UpdateSessionRequest{SessionId: session, Actor: account, Data: data, SetData: true})
	return err
}

func (m *MatchmakingCore) Heartbeat(ctx context.Context, account string) {
	m.C.Heartbeat(m.ctx(ctx), &pb.HeartbeatRequest{AccountId: account})
}

// RoomInfo is one search result. Owner is the owner's core account id; the agent resolves its name at read time.
type RoomInfo struct {
	ID      string
	RoomID  uint64
	Owner   string
	Network string // the network the room was created from ("np", "wiiu", ...)
	Max     uint32
	Members uint32
	Attrs   wire.RoomAttrs // the attributes the host set
}

// SearchRooms lists open rooms of the title in the searcher's compatibility group (forced by the caller: a PS3 only sees old-gen-1.2.4
// rooms) created from the given networks (never empty: "np" alone keeps the search inside the PS3 network).
func (m *MatchmakingCore) SearchRooms(ctx context.Context, title, compat string, networks []string, limit uint32, filters []wire.SearchFilter) ([]RoomInfo, error) {
	fs := []*pb.Filter{{Attr: "compat", Op: "eq", IsString: true, StringValue: compat}}
	for _, f := range filters {
		if op := filterOps[f.Op]; op != "" {
			fs = append(fs, &pb.Filter{Attr: fmt.Sprintf("i%02x", f.Attr), Op: op, IntValue: int64(f.Value)})
		}
	}
	res, err := m.C.SearchSessions(m.ctx(ctx), &pb.SearchSessionsRequest{
		Title: &pb.TitleRef{Network: "np", Title: title}, Network: "np", Networks: networks, Kind: "room", OnlyWithFreeSlots: true, Limit: limit,
		Filters: fs,
	})
	if err != nil {
		return nil, err
	}
	var out []RoomInfo
	for _, x := range res.GetSessions() {
		ri := RoomInfo{ID: x.GetId(), RoomID: roomIDOf(x.GetId()), Owner: x.GetOwnerId(), Network: x.GetTitle().GetNetwork(), Max: x.GetMaxMembers(), Attrs: attrsFromPB(x.GetAttrs())}
		for _, a := range x.GetAttrs() {
			if a.GetName() == "$members" {
				ri.Members = uint32(a.GetIntValue())
			}
		}
		out = append(out, ri)
	}
	return out, nil
}

// JoinedRoom is a session the account has joined.
type JoinedRoom struct {
	ID       string
	RoomID   uint64
	MemberNo uint32
	Max      uint32
	Members  []RoomMember
	Attrs    wire.RoomAttrs
}

// RoomMember is a member as the core holds it: a number, a core account id (the agent resolves the name) and the member's published
// public UDP endpoint (Addr = IPv4 bytes, empty when none) with its NAT type.
type RoomMember struct {
	No      uint32
	Account string
	Addr    []byte
	NAT     byte
	Owner   bool
	Bin     []byte // the member's 0x59 bin attr (member data in the core)
}

func memberOf(mm *pb.Member) RoomMember {
	r := RoomMember{No: mm.GetMemberNo(), Account: mm.GetAccountId(), Owner: mm.GetIsOwner(), Bin: mm.GetData()}
	for _, e := range mm.GetEndpoints() {
		if e.GetKind() != "udp" {
			continue
		}
		if ip := net.ParseIP(e.GetHost()).To4(); ip != nil {
			r.Addr, r.NAT = []byte(ip), byte(e.GetNatType())
			break
		}
	}
	return r
}

// SignalPort is the PS3's signaling UDP port (the SceNp2 signaling default, inferred): published with the console's address so other
// networks' adapters and the relay know where to reach it.
const SignalPort = 3658

// SetEndpoints publishes a member's public address (the 4 bytes of its 0x6e member attr) and NAT type in the core: kind "udp",
// port SignalPort. This is the shared contract with the cross-network relay (prds#145).
func (m *MatchmakingCore) SetEndpoints(ctx context.Context, session, account string, addr []byte, nat byte) error {
	if len(addr) != 4 {
		return nil
	}
	_, err := m.C.SetEndpoints(m.ctx(ctx), &pb.SetEndpointsRequest{SessionId: session, AccountId: account,
		Endpoints: []*pb.Endpoint{{Kind: "udp", Host: net.IP(addr).String(), Port: SignalPort, NatType: uint32(nat)}}})
	return err
}

// Members lists a room's members as the viewer (a member) sees them, endpoints included.
func (m *MatchmakingCore) Members(ctx context.Context, session, viewer string) ([]RoomMember, error) {
	res, err := m.C.GetSession(m.ctx(ctx), &pb.GetSessionRequest{SessionId: session, Viewer: viewer})
	if err != nil {
		return nil, err
	}
	var out []RoomMember
	for _, mm := range res.GetSession().GetMembers() {
		out = append(out, memberOf(mm))
	}
	return out, nil
}

// RoomEvent is a core event delivered to one account.
type RoomEvent struct {
	Type     string // "member_joined", "member_left", "member_updated", "owner_changed", "session_ended", "signal", ...
	Session  string
	Subject  string // the account the event is about
	To       string
	MemberNo uint32
	Text     string
	Payload  []byte
}

// Watch streams the core's events for account until ctx ends or the stream breaks.
func (m *MatchmakingCore) Watch(ctx context.Context, account string, fn func(RoomEvent)) error {
	st, err := m.C.Watch(m.ctx(ctx), &pb.WatchRequest{Accounts: []string{account}})
	if err != nil {
		return err
	}
	for {
		ev, err := st.Recv()
		if err != nil {
			return err
		}
		fn(RoomEvent{Type: strings.ToLower(strings.TrimPrefix(ev.GetType().String(), "EVENT_TYPE_")), Session: ev.GetSessionId(),
			Subject: ev.GetAccountId(), To: ev.GetTo(), MemberNo: ev.GetMemberNo(), Text: ev.GetText(), Payload: ev.GetPayload()})
	}
}

func (m *MatchmakingCore) JoinRoom(ctx context.Context, session, account string, memberBin []byte) (*JoinedRoom, error) {
	res, err := m.C.JoinSession(m.ctx(ctx), &pb.JoinSessionRequest{SessionId: session, AccountId: account, Network: "np", MemberData: memberBin})
	if err != nil {
		return nil, err
	}
	j := &JoinedRoom{ID: session, RoomID: roomIDOf(session), MemberNo: res.GetMemberNo(), Max: res.GetSession().GetMaxMembers(), Attrs: attrsFromPB(res.GetSession().GetAttrs())}
	for _, mm := range res.GetSession().GetMembers() {
		j.Members = append(j.Members, memberOf(mm))
	}
	return j, nil
}

// GetRoom reads a room as a member sees it: attributes and members (the viewer's own member number is not known here, MemberNo is 0).
func (m *MatchmakingCore) GetRoom(ctx context.Context, session, viewer string) (*JoinedRoom, error) {
	res, err := m.C.GetSession(m.ctx(ctx), &pb.GetSessionRequest{SessionId: session, Viewer: viewer})
	if err != nil {
		return nil, err
	}
	s := res.GetSession()
	j := &JoinedRoom{ID: session, RoomID: roomIDOf(session), Max: s.GetMaxMembers(), Attrs: attrsFromPB(s.GetAttrs())}
	for _, mm := range s.GetMembers() {
		j.Members = append(j.Members, memberOf(mm))
	}
	return j, nil
}

// SetRoomAttrs merges the attributes into the room (the owner's SetRoomDataInternal / SetRoomDataExternal).
func (m *MatchmakingCore) SetRoomAttrs(ctx context.Context, session, account string, a wire.RoomAttrs) error {
	if a.Empty() {
		return nil
	}
	_, err := m.C.UpdateSession(m.ctx(ctx), &pb.UpdateSessionRequest{SessionId: session, Actor: account, SetAttrs: attrsToPB(a)})
	return err
}

// SetMemberBin replaces the member's 0x59 bin attr (SetRoomMemberDataInternal); actor may be the member or the room owner.
func (m *MatchmakingCore) SetMemberBin(ctx context.Context, session, actor, account string, bin []byte) error {
	_, err := m.C.UpdateMember(m.ctx(ctx), &pb.UpdateMemberRequest{SessionId: session, AccountId: account, Actor: actor, Data: bin, SetData: true})
	return err
}

// KickMember removes a member from the room (the owner's KickoutRoomMember).
func (m *MatchmakingCore) KickMember(ctx context.Context, session, actor, account string) error {
	_, err := m.C.KickMember(m.ctx(ctx), &pb.KickMemberRequest{SessionId: session, AccountId: account, Actor: actor})
	return err
}
