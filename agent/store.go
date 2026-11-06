package agent

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store keeps the agent's protocol state: login sessions (the MAC key a console was handed) and the per-member room keys
// (the MAC key of a member's room requests and events). Rooms themselves live in the matchmaking core.
type Store struct{ DB *pgxpool.Pool }

const schema = `
CREATE TABLE IF NOT EXISTS m2_sessions (
    id        BIGSERIAL PRIMARY KEY,
    comm_id   TEXT NOT NULL,
    account   UUID NOT NULL,
    online_id TEXT NOT NULL,
    key       BYTEA NOT NULL,
    created   TIMESTAMPTZ NOT NULL,
    expires   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS m2_sessions_comm ON m2_sessions (comm_id, expires);
CREATE INDEX IF NOT EXISTS m2_sessions_account ON m2_sessions (account);
CREATE TABLE IF NOT EXISTS m2_room_keys (
    room      UUID NOT NULL,
    account   UUID NOT NULL,
    key       BYTEA NOT NULL,
    created   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (room, account)
);
CREATE INDEX IF NOT EXISTS m2_room_keys_account ON m2_room_keys (account, created DESC);
CREATE INDEX IF NOT EXISTS m2_room_keys_created ON m2_room_keys (created);
`

func OpenStore(ctx context.Context, url string) (*Store, error) {
	p, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := p.Exec(ctx, schema); err != nil {
		p.Close()
		return nil, err
	}
	return &Store{DB: p}, nil
}

func (s *Store) Close() { s.DB.Close() }

// Session is one login.
type Session struct {
	ID       int64
	Comm     string
	Account  string
	OnlineID string
	Key      []byte
	Expires  time.Time
}

func (s *Store) Create(ctx context.Context, comm, account, online string, key []byte, ttl time.Duration) (*Session, error) {
	now := time.Now().UTC()
	x := &Session{Comm: comm, Account: account, OnlineID: online, Key: key, Expires: now.Add(ttl)}
	err := s.DB.QueryRow(ctx, `INSERT INTO m2_sessions (comm_id,account,online_id,key,created,expires) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		comm, account, online, key, now, x.Expires).Scan(&x.ID)
	return x, err
}

// Active lists the unexpired sessions of a title, newest first: a request after login carries no identity, so
// the agent finds the login whose key verifies the request's MAC.
func (s *Store) Active(ctx context.Context, comm string) ([]*Session, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, comm_id, account::text, online_id, key, expires FROM m2_sessions WHERE comm_id=$1 AND expires > now() ORDER BY id DESC LIMIT 500`, comm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		var x Session
		if err := rows.Scan(&x.ID, &x.Comm, &x.Account, &x.OnlineID, &x.Key, &x.Expires); err != nil {
			return nil, err
		}
		out = append(out, &x)
	}
	return out, rows.Err()
}

func (s *Store) Extend(ctx context.Context, id int64, ttl time.Duration) error {
	_, err := s.DB.Exec(ctx, `UPDATE m2_sessions SET expires=$2 WHERE id=$1`, id, time.Now().UTC().Add(ttl))
	return err
}

func (s *Store) Purge(ctx context.Context) (int64, error) {
	t, err := s.DB.Exec(ctx, `DELETE FROM m2_sessions WHERE expires < now() - interval '1 hour'`)
	if err != nil {
		return 0, err
	}
	k, err := s.DB.Exec(ctx, `DELETE FROM m2_room_keys WHERE created < now() - interval '2 days'`)
	return t.RowsAffected() + k.RowsAffected(), err
}

// RoomKey is one member's key for a room: the MAC key of that member's 0x31xx/0x32xx requests, replies and events.
type RoomKey struct {
	Room    string
	Account string
	Key     []byte
}

// PutRoomKey stores (or replaces) a member's room key.
func (s *Store) PutRoomKey(ctx context.Context, room, account string, key []byte) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO m2_room_keys (room,account,key,created) VALUES ($1,$2,$3,$4)
ON CONFLICT (room,account) DO UPDATE SET key=EXCLUDED.key, created=EXCLUDED.created`, room, account, key, time.Now().UTC())
	return err
}

// GetRoomKey returns a member's room key, or nil.
func (s *Store) GetRoomKey(ctx context.Context, room, account string) ([]byte, error) {
	var k []byte
	err := s.DB.QueryRow(ctx, `SELECT key FROM m2_room_keys WHERE room=$1 AND account=$2`, room, account).Scan(&k)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return k, err
}

// RecentRoomKeys lists the room keys of the last day, newest first: a room request on a fresh connection names nobody, so the
// agent finds its member by the MAC.
func (s *Store) RecentRoomKeys(ctx context.Context, account string) ([]RoomKey, error) {
	q, args := `SELECT room::text, account::text, key FROM m2_room_keys WHERE created > now() - interval '1 day' ORDER BY created DESC LIMIT 2000`, []any{}
	if account != "" {
		q, args = `SELECT room::text, account::text, key FROM m2_room_keys WHERE account=$1 AND created > now() - interval '1 day' ORDER BY created DESC LIMIT 50`, []any{account}
	}
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RoomKey
	for rows.Next() {
		var k RoomKey
		if err := rows.Scan(&k.Room, &k.Account, &k.Key); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SessionOf returns the newest unexpired login of an account for a title, or nil.
func (s *Store) SessionOf(ctx context.Context, comm, account string) (*Session, error) {
	all, err := s.Active(ctx, comm)
	if err != nil {
		return nil, err
	}
	for _, x := range all {
		if x.Account == account {
			return x, nil
		}
	}
	return nil, nil
}

// Erase removes every session of an account (account erasure).
func (s *Store) Erase(ctx context.Context, account string) (int64, error) {
	t, err := s.DB.Exec(ctx, `DELETE FROM m2_sessions WHERE account=$1`, account)
	if err != nil {
		return 0, err
	}
	k, err := s.DB.Exec(ctx, `DELETE FROM m2_room_keys WHERE account=$1`, account)
	return t.RowsAffected() + k.RowsAffected(), err
}
