package agent

import (
	"context"

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
