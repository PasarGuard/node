//go:build !windows

package mtproto

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pasarguard/node/pkg/logstream"
)

// TestProcessManager_LogsReachSubscribersAndCloseCleanly runs a stand-in for
// telemt that writes to stdout and stderr, then shuts it down and closes the
// log buffer while a subscriber is attached. Neither step may panic, and the
// subscriber channel must be closed afterwards.
func TestProcessManager_LogsReachSubscribersAndCloseCleanly(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}

	dir := t.TempDir()
	p := &processManager{
		executablePath: sh,
		configPath:     filepath.Join(dir, "config.toml"),
		pidFilePath:    filepath.Join(dir, "telemt.pid"),
		logs:           logstream.NewBuffer(16),
		commandFactory: func(executable string, _ ...string) *exec.Cmd {
			return exec.Command(executable, "-c", "echo out-line; echo err-line >&2; exec sleep 30")
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := p.SubscribeLogs(ctx)

	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	seen := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for !seen["out-line"] || !seen["err-line"] {
		select {
		case line := <-logs:
			seen[line] = true
		case <-deadline:
			t.Fatalf("timed out waiting for stdout and stderr lines, got %v", seen)
		}
	}

	p.Shutdown()
	p.logs.Close()

	select {
	case _, ok := <-logs:
		if ok {
			t.Fatal("expected the subscriber channel to be closed after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber channel was not closed after Close")
	}

	if _, ok := <-p.SubscribeLogs(context.Background()); ok {
		t.Fatal("expected a closed channel when subscribing after Close")
	}
}
