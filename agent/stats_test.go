package agent

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestStatsSummaryAndQuiet(t *testing.T) {
	var s Stats
	for i := 0; i < 100; i++ {
		s.Observe(0x1007, true, 2*time.Millisecond)
	}
	s.Observe(0x1209, false, time.Millisecond)
	var b bytes.Buffer
	s.Flush(slog.New(slog.NewTextHandler(&b, nil)))
	out := b.String()
	if strings.Count(out, "\n") != 1 || !strings.Contains(out, "cmd_1007") || !strings.Contains(out, "n=100") || !strings.Contains(out, "no_reply=1") {
		t.Fatalf("one summary line expected, got %q", out)
	}
	b.Reset()
	s.Flush(slog.New(slog.NewTextHandler(&b, nil)))
	if b.Len() != 0 {
		t.Fatal("an idle minute must log nothing")
	}
	if s.Quiet("k") || !s.Quiet("k") {
		t.Fatal("first call logs, repeats within a minute are quiet")
	}
}
