package hysteria

import (
	"path/filepath"
	"testing"
	"time"

	nodeLogger "github.com/pasarguard/node/logger"
)

// TestHysteriaImplementsLogLiner is the gate for this file. The controller picks
// the classified stream by type-asserting for nodeLogger.LogLiner and silently
// falls back to the plain string channel when the assertion fails — no error, no
// log line: every hysteria record just arrives with an empty level, so the
// panel's level filter can never match one. A type assertion is therefore the
// whole feature, and it needs asserting.
func TestHysteriaImplementsLogLiner(t *testing.T) {
	var _ nodeLogger.LogLiner = (*Hysteria)(nil)
	var _ nodeLogger.LogLiner = (*Core)(nil)
}

// TestCoreLogLinesCarriesTheLevel proves the level reaches the record, not just
// the file. Without a logger there is nothing to carry it, so this asserts the
// nil case too: a consumer attaching before SetLogger must get a nil channel
// rather than a panic.
//
// The channel exists only once the Logger is bound to a core, and binding
// derives the id from the config directory's name (logger/logger.go:92-104), so
// the fixture has to name it `core-<id>` like a real generated-config path.
func TestCoreLogLinesCarriesTheLevel(t *testing.T) {
	c := &Core{}
	if ch := c.LogLines(); ch != nil {
		t.Fatal("a Core with no logger must yield a nil channel, not a live one")
	}

	c.configDir = filepath.Join(t.TempDir(), "core-7")
	c.logger = nodeLogger.New(false)
	// Binding opens a per-core log file; without this the Windows TempDir
	// cleanup fails on an unclosed handle, which is a test failure about the
	// fixture rather than about the thing under test.
	t.Cleanup(c.logger.Close)

	ch := c.LogLines()
	if ch == nil {
		t.Fatal("a bound Core with a logger must yield a live classified channel")
	}

	c.logger.Log(nodeLogger.LogWarning, "a line")
	select {
	case line := <-ch:
		if line.Level != nodeLogger.LogWarning {
			t.Fatalf("level did not survive onto the record: got %q, want %q", line.Level, nodeLogger.LogWarning)
		}
		if line.Detail != "a line" {
			t.Fatalf("detail did not survive onto the record: got %q", line.Detail)
		}
		if line.TsUnixMs == 0 {
			t.Fatal("record has no timestamp; the panel renders it as a blank column")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("classified channel produced nothing for a logged line")
	}
}

// TestHysteriaLogLinesIsNilSafe: the controller holds the outer Hysteria, and
// reads its core under a lock. A nil receiver or a nil core must not panic —
// that runs inside the GetLogs handler, so a panic there takes down the whole
// log stream rather than one core's lines.
func TestHysteriaLogLinesIsNilSafe(t *testing.T) {
	var h *Hysteria
	if ch := h.LogLines(); ch != nil {
		t.Fatal("a nil Hysteria must yield a nil channel")
	}
	if ch := (&Hysteria{}).LogLines(); ch != nil {
		t.Fatal("a Hysteria with no core must yield a nil channel")
	}
}

// TestLevelForLineIsTheOneAlreadyChoosingTheFile pins the classification the
// record now carries to the one the node has always used for the file, so the
// two cannot drift apart.
func TestLevelForLineIsTheOneAlreadyChoosingTheFile(t *testing.T) {
	cases := []struct {
		line string
		want nodeLogger.LogLevel
	}{
		{"FATAL  failed to load server config", nodeLogger.LogError},
		{"ERROR something went wrong", nodeLogger.LogError},
		{"WARN  slow client", nodeLogger.LogWarning},
		{"INFO  serving on :443", nodeLogger.LogInfo},
		{"a line with no level word", nodeLogger.LogInfo},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			if got := levelForLine(tc.line); got != tc.want {
				t.Fatalf("levelForLine(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}
