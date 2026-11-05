package agent

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/openpak/matchmaking/proto/openpak/matchmaking/v1"
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

// Worlds counts the open and closed rooms of a title and their members.
func (m *MatchmakingCore) Worlds(ctx context.Context, title string) (uint32, uint32, error) {
	res, err := m.C.SearchSessions(m.ctx(ctx), &pb.SearchSessionsRequest{Title: &pb.TitleRef{Network: "np", Title: title}, IncludeClosed: true, Limit: 100})
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

func roomIDOf(session string) uint64 {
	b, err := hex.DecodeString(strings.ReplaceAll(session, "-", ""))
	if err != nil || len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b[:8])
}

// CreateRoom opens a Terraria room for the account: kind room under the neutral title key, attributes for the unified service
// (compat group and console), the console's own request kept in the data blob.
func (m *MatchmakingCore) CreateRoom(ctx context.Context, title, account, display string, maxSlot uint32, data []byte) (*Room, error) {
	res, err := m.C.CreateSession(m.ctx(ctx), &pb.CreateSessionRequest{
		Title: &pb.TitleRef{Network: "np", Title: title}, Creator: account, DisplayName: display, Network: "np", Kind: "room",
		MaxMembers: maxSlot, MigrateOwner: true, TtlSeconds: 300, Data: data,
		Attrs: []*pb.Attr{
			{Name: "compat", Type: pb.AttrType_ATTR_TYPE_STRING, StringValue: "old-gen-1.2.4", Searchable: true},
			{Name: "console", Type: pb.AttrType_ATTR_TYPE_STRING, StringValue: "ps3", Searchable: true},
		},
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
