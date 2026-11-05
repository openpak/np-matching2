package agent

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Stats counts requests per command so the normal log line is one summary a minute instead of one line per request
// (Terraria polls GetUserInfoList about ten times a second). Per-request lines are Debug.
type Stats struct {
	mu   sync.Mutex
	m    map[uint16]*stat
	last map[string]time.Time
}

type stat struct {
	n, noReply int
	total      time.Duration
}

func (s *Stats) Observe(cmd uint16, replied bool, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[uint16]*stat{}
	}
	x := s.m[cmd]
	if x == nil {
		x = &stat{}
		s.m[cmd] = x
	}
	x.n++
	x.total += d
	if !replied {
		x.noReply++
	}
}

// Flush logs the counts since the last flush (nothing when idle) and resets them.
func (s *Stats) Flush(log *slog.Logger) {
	s.mu.Lock()
	m := s.m
	s.m = nil
	s.mu.Unlock()
	if len(m) == 0 {
		return
	}
	cmds := make([]int, 0, len(m))
	for c := range m {
		cmds = append(cmds, int(c))
	}
	sort.Ints(cmds)
	attrs := []any{}
	for _, c := range cmds {
		x := m[uint16(c)]
		attrs = append(attrs, fmt.Sprintf("cmd_%04x", c), fmt.Sprintf("n=%d no_reply=%d avg_ms=%.1f", x.n, x.noReply, float64(x.total.Microseconds())/1000/float64(x.n)))
	}
	log.Info("matching2 requests (last minute)", attrs...)
}

// Run flushes every minute until stop closes.
func (s *Stats) Run(log *slog.Logger, stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.Flush(log)
		case <-stop:
			s.Flush(log)
			return
		}
	}
}

// Quiet reports whether a message with this key may be logged now: once a minute per key, so a retry loop leaves
// one line (the Stats summary still counts every request).
func (s *Stats) Quiet(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		s.last = map[string]time.Time{}
	}
	if t, ok := s.last[key]; ok && time.Since(t) < time.Minute {
		return true
	}
	s.last[key] = time.Now()
	return false
}
