// Command np-matching2 is the PS3 Matching2 agent: plain TCP (3480) and TLS (8443, the no-SNI front) listeners
// speaking the firmware's wire, over the neutral matchmaking core.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"openpak/np-common/coreclient"
	"openpak/np-common/nphttp"
	"openpak/np-common/ticket"
	"openpak/np-common/tlsfront"
	"openpak/np-matching2/agent"
	"openpak/np-matching2/front"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("np-matching2 stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	lvl := slog.LevelInfo
	if os.Getenv("NP_LOG_LEVEL") == "debug" {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// NP_MATCHING_TITLES: {"NPWR04270_00": {"title": "terraria", "passphrase": "<256 hex>"}}
	raw, err := os.ReadFile(os.Getenv("NP_MATCHING_TITLES"))
	if err != nil {
		return fmt.Errorf("NP_MATCHING_TITLES: %w", err)
	}
	var cfg map[string]struct{ Title, Passphrase string }
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("NP_MATCHING_TITLES: %w", err)
	}
	titles := map[string]agent.Title{}
	for id, t := range cfg {
		p, err := hex.DecodeString(t.Passphrase)
		if err != nil || len(p) != 128 || t.Title == "" {
			return fmt.Errorf("NP_MATCHING_TITLES %s: want title and a 256-hex passphrase", id)
		}
		titles[id] = agent.Title{Key: t.Title, Pass: p}
	}
	store, err := agent.OpenStore(ctx, os.Getenv("NP_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	signer, err := ticket.Load(os.Getenv("NP_TICKET_KEY"))
	if err != nil {
		return err
	}
	acct, err := coreclient.Dial(nphttp.Env("NP_CORE_ADDR", "localhost:7000"), os.Getenv("NP_CORE_KEY"))
	if err != nil {
		return err
	}
	defer acct.Close()
	mm, conn, err := agent.DialMatchmaking(os.Getenv("NP_MATCHMAKING_ADDR"), os.Getenv("NP_MATCHMAKING_KEY"))
	if err != nil {
		return err
	}
	defer conn.Close()
	a := &agent.Agent{Titles: titles, Store: store, Tickets: signer, Account: acct, Core: mm, Log: log, RoomHost: nphttp.Env("NP_MATCHING_HOST", "matching.np.community.playstation.net"), RoomPort: 3480}

	if dir := os.Getenv("NP_CAPTURE_DIR"); dir != "" {
		os.MkdirAll(dir, 0o700)
		a.Capture = &agent.Capture{Dir: dir}
	}
	go a.Stats.Run(log, ctx.Done())
	go func() {
		for range time.Tick(time.Hour) {
			store.Purge(ctx)
		}
	}()

	plain, err := net.Listen("tcp", nphttp.Env("NP_PLAIN_ADDR", ":3480"))
	if err != nil {
		return err
	}
	go serve(plain, a.ServePlain)

	// TLS side: the firmware's no-SNI hello is told from D2R's by front.Classify; D2R keeps the old path.
	ca, err := tlsfront.Load(os.Getenv("NP_TLS_CA_CERT"), os.Getenv("NP_TLS_CA_KEY"))
	if err != nil {
		return err
	}
	ca.Fallback = nphttp.Env("NP_MATCHING_HOST", "matching.np.community.playstation.net")
	tlsCfg := ca.Config()
	legacy := func(c net.Conn) { a.ServeTLS(tls.Server(c, tlsCfg)) }
	other := func(c net.Conn) { c.Close() }
	if f := os.Getenv("NP_NOSNI_CERT"); f != "" {
		o, err := front.Terminate(f, os.Getenv("NP_NOSNI_KEY"), os.Getenv("NP_NOSNI_TARGET"))
		if err != nil {
			return err
		}
		other = o
	}
	tl, err := net.Listen("tcp", nphttp.Env("NP_TLS_ADDR", ":8443"))
	if err != nil {
		return err
	}
	go front.Serve(tl, front.Handlers{Legacy: legacy, Other: other, Log: log, AgentHost: ca.Fallback})

	mux := http.NewServeMux()
	a.Register(mux)
	nphttp.Health(mux)
	log.Info("np-matching2 up", "titles", len(titles))
	return nphttp.Run(ctx, mux, nphttp.Env("NP_HTTP_ADDR", ":8538"), "", nil)
}

func serve(ln net.Listener, h func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go h(c)
	}
}
