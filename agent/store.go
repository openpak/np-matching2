package agent

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store keeps the agent's protocol state: login sessions (the MAC key a console was handed). Nothing about
// rooms lives here; that is the matchmaking core.
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
	return t.RowsAffected(), err
}

// Erase removes every session of an account (account erasure).
func (s *Store) Erase(ctx context.Context, account string) (int64, error) {
	t, err := s.DB.Exec(ctx, `DELETE FROM m2_sessions WHERE account=$1`, account)
	return t.RowsAffected(), err
}
