package agent

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Capture appends every non-polling request and its reply as JSON lines (redacted hex: ticket, passphrase and session key values are
// overwritten) to NP_CAPTURE_DIR/matching2-YYYY-MM-DD.jsonl, mode 0600, files older than 90 days removed. It is how a real console's Matching2
// traffic is recorded for the next protocol step. Polling commands (ping, renew, user info) are counted by Stats instead.
type Capture struct {
	Dir string
	mu  sync.Mutex
	day string
	f   *os.File
}

var polling = map[uint16]bool{0x1001: true, 0x1003: true, 0x1007: true}

// Record keeps one request and its reply; conn is the agent's connection id (conn.id, also in the logs).
func (c *Capture) Record(cmd uint16, title, account string, conn uint64, req, reply []byte) {
	if c == nil || c.Dir == "" || polling[cmd] {
		return
	}
	c.write(map[string]any{"cmd": cmd, "title": title, "account": account, "conn": conn, "req": hex.EncodeToString(req), "reply": hex.EncodeToString(reply)})
}

// Event keeps one pushed packet (kind 4) with the connection it went out on; variant names an experiment attempt (experiment.go).
func (c *Capture) Event(conn uint64, account string, code uint16, variant string, pkt []byte) {
	if c == nil || c.Dir == "" {
		return
	}
	c.write(map[string]any{"cmd": code, "account": account, "conn": conn, "pushed": true, "variant": variant, "event": hex.EncodeToString(pkt)})
}

func (c *Capture) write(rec map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UTC()
	if d := now.Format("2006-01-02"); d != c.day || c.f == nil {
		if c.f != nil {
			c.f.Close()
		}
		f, err := os.OpenFile(filepath.Join(c.Dir, "matching2-"+d+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		c.f, c.day = f, d
		c.prune(now)
	}
	rec["t"] = now.Format(time.RFC3339Nano)
	line, _ := json.Marshal(rec)
	c.f.Write(append(line, '\n'))
}

func (c *Capture) prune(now time.Time) {
	ents, _ := os.ReadDir(c.Dir)
	for _, e := range ents {
		if i, err := e.Info(); err == nil && now.Sub(i.ModTime()) > 90*24*time.Hour {
			os.Remove(filepath.Join(c.Dir, e.Name()))
		}
	}
}
