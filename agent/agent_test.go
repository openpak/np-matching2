// The handshake through the agent against a real Postgres (NP_MATCHING_TEST_DATABASE_URL) with the headless client:
// ping, login with a real ticket, world list from a fake core, renew, MAC refusals, erasure. Skipped without a database.
package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"openpak/np-common/ticket"
	"openpak/np-matching2/agent"
	"openpak/np-matching2/client"
	"openpak/np-matching2/wire"
)

type fakeCore struct{ rooms, members uint32 }

func (f fakeCore) Worlds(context.Context, string) (uint32, uint32, error) {
	return f.rooms, f.members, nil
}

func TestHandshake(t *testing.T) {
	url := os.Getenv("NP_MATCHING_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("NP_MATCHING_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	st, err := agent.OpenStore(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.DB.Exec(ctx, `TRUNCATE m2_sessions`)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ticket.New(priv, nil)
	pass := make([]byte, 128)
	rand.Read(pass)
	const acct = "11111111-1111-1111-1111-111111111111"
	a := &agent.Agent{Titles: map[string]agent.Title{"NPWR04270_00": {Key: "terraria", Pass: pass}}, Store: st, Tickets: signer, Core: fakeCore{rooms: 3, members: 5}}

	pair := func(h func(net.Conn)) net.Conn {
		c, s := net.Pipe()
		go h(s)
		return c
	}
	c := &client.Client{Comm: "NPWR04270_00", Pass: pass, Plain: pair(a.ServePlain), TLS: pair(a.ServeTLS)}

	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(wire.CmdWorldList); err == nil {
		t.Fatal("a request before login must not be answered")
	}
	tk, err := signer.Issue(ticket.Identity{AccountID: acct, LinkID: "l", OnlineID: "PS3Test", Country: "pt", Service: "IV0001-NPXS01001_00"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Login(tk, "PS3Test", "PS3 Test User"); err != nil || len(c.Key) != 20 {
		t.Fatalf("login: %v", err)
	}

	// a fresh plain connection finds the session by its MAC
	c.Plain = pair(a.ServePlain)
	c.Plain.Write([]byte{0})
	if _, err := c.Ping(); err != nil {
		t.Fatal(err)
	}
	f, err := c.Call(wire.CmdWorldList)
	if err != nil {
		t.Fatal(err)
	}
	w := f.Elements()[0x02]
	if len(w) < 4+4+18 || w[3] != 1 || w[4+4+12] != 0 || w[4+4+13] != 3 {
		t.Fatalf("world list %x", w)
	}
	if f, err = c.Call(wire.CmdRenew); err != nil || len(f.Elements()[0x5d]) != 16 {
		t.Fatalf("renew: %v", err)
	}

	// a stranger's key is not answered; a wrong passphrase cannot log in
	bad := &client.Client{Comm: "NPWR04270_00", Pass: pass, Plain: pair(a.ServePlain), Key: make([]byte, 20)}
	bad.Plain.Write([]byte{0})
	if _, err := bad.Call(wire.CmdWorldList); err == nil {
		t.Fatal("unknown key answered")
	}
	wrong := &client.Client{Comm: "NPWR04270_00", Pass: append([]byte{1}, pass[1:]...), TLS: pair(a.ServeTLS)}
	if _, err := wrong.Login(tk, "PS3Test", "x"); err == nil {
		t.Fatal("login with the wrong passphrase")
	}

	// erasure
	t.Setenv("ACCOUNT_ERASE_KEY", "k")
	mux := http.NewServeMux()
	a.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest("DELETE", srv.URL+"/internal/accounts/"+acct+"/data", nil)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 401 {
		t.Fatal("erase needs the key")
	}
	req.Header.Set("Authorization", "Bearer k")
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != 200 {
		t.Fatal("erase")
	}
	var n int
	st.DB.QueryRow(ctx, `SELECT count(*) FROM m2_sessions WHERE account=$1`, acct).Scan(&n)
	if n != 0 {
		t.Fatal("sessions survive erasure")
	}
}
