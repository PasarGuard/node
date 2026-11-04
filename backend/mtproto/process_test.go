//go:build !windows

package mtproto

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestProcessManager builds a process manager for the fake telemt and
// closes it when the test ends, so a failing test never leaves a child running.
func newTestProcessManager(t *testing.T, f fakeTelemt) *processManager {
	t.Helper()

	manager, err := newProcessManager(writeFakeTelemt(t, f), t.TempDir(), 500, 50)
	if err != nil {
		t.Fatalf("newProcessManager: %v", err)
	}
	t.Cleanup(manager.Close)
	return manager
}

func TestParseTelemtVersion(t *testing.T) {
	for output, want := range map[string]string{
		"telemt 3.5.14\n":      "3.5.14",
		"telemt 3.5.15":        "3.5.15",
		"telemt 3.6.0\n":       "3.6.0",
		"telemt 4.0.0":         "4.0.0",
		"telemt 3.5.14-rc.1\n": "3.5.14-rc.1",
	} {
		got, err := parseTelemtVersion(output)
		if err != nil || got != want {
			t.Errorf("parseTelemtVersion(%q) = %q, %v; want %q", output, got, err, want)
		}
	}

	for _, output := range []string{"telemt 3.5.13", "telemt 3.4.25", "telemt 2.9.99", "", "garbage", "telemt x.y.z"} {
		if _, err := parseTelemtVersion(output); err == nil {
			t.Errorf("parseTelemtVersion(%q) succeeded, want an error", output)
		}
	}
}

func TestProcessRefusesOldTelemt(t *testing.T) {
	_, err := newProcessManager(writeFakeTelemt(t, fakeTelemt{Version: "3.4.25"}), t.TempDir(), 16, 50)
	if err == nil {
		t.Fatal("newProcessManager accepted telemt 3.4.25")
	}
	if !strings.Contains(err.Error(), "3.5.14") || !strings.Contains(err.Error(), "3.4.25") {
		t.Errorf("error %q should name the found version and the 3.5.14 floor", err)
	}
}

func TestProcessAcceptsSupportedTelemt(t *testing.T) {
	manager := newTestProcessManager(t, fakeTelemt{})
	if got := manager.Version(); got != "3.5.14" {
		t.Errorf("Version() = %q, want 3.5.14", got)
	}
	if manager.Started() || manager.PID() != 0 || manager.Exited() != nil || manager.Generation() != 0 {
		t.Error("a new process manager must report not started, pid 0, nil Exited and generation 0")
	}
}

func TestProcessRunArgsHaveNoPidFile(t *testing.T) {
	record := filepath.Join(t.TempDir(), "record.json")
	manager := newTestProcessManager(t, fakeTelemt{RecordFile: record, NoAPI: true})

	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := manager.Start(configPath); err != nil {
		t.Fatalf("Start: %v", err)
	}

	got := readFakeTelemtRecord(t, record)
	if want := []string{"run", configPath}; !slices.Equal(got.Args, want) {
		t.Errorf("telemt argv = %q, want %q", got.Args, want)
	}
	wantDir, err := filepath.EvalSymlinks(manager.workDir)
	if err != nil {
		t.Fatal(err)
	}
	if gotDir, _ := filepath.EvalSymlinks(got.Cwd); gotDir != wantDir {
		t.Errorf("telemt cwd = %q, want the work dir %q", got.Cwd, wantDir)
	}
	if manager.PID() != got.PID {
		t.Errorf("PID() = %d, want %d", manager.PID(), got.PID)
	}
	if manager.Generation() != 1 {
		t.Errorf("Generation() = %d, want 1", manager.Generation())
	}
	if err := manager.Start(configPath); err == nil {
		t.Error("a second Start while telemt runs must fail")
	}
}

// TestProcessStartedNoRace must run under -race: Started reads process state
// while the wait goroutine reaps the exiting child.
func TestProcessStartedNoRace(t *testing.T) {
	manager := newTestProcessManager(t, fakeTelemt{NoAPI: true, ExitAfter: 50 * time.Millisecond})

	if err := manager.Start(filepath.Join(t.TempDir(), "config.toml")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	exited := manager.Exited()
	if exited == nil {
		t.Fatal("Exited() is nil after Start")
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				_ = manager.Started()
				_ = manager.PID()
				_ = manager.Generation()
				select {
				case <-exited:
					return
				default:
				}
			}
		}()
	}

	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the fake telemt did not exit")
	}
	wg.Wait()

	if manager.Started() {
		t.Error("Started() is true after the process exited")
	}
}

func TestProcessLogsReachSubscribersAndCloseCleanly(t *testing.T) {
	manager := newTestProcessManager(t, fakeTelemt{NoAPI: true, Stdout: []string{"out-line"}, Stderr: []string{"err-line"}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logs := manager.SubscribeLogs(ctx)

	if err := manager.Start(filepath.Join(t.TempDir(), "config.toml")); err != nil {
		t.Fatalf("Start: %v", err)
	}

	seen := map[string]bool{}
	deadline := time.After(10 * time.Second)
	for !seen["out-line"] || !seen["err-line"] {
		select {
		case line := <-logs:
			seen[line] = true
		case <-deadline:
			t.Fatalf("timed out waiting for stdout and stderr lines, got %v", seen)
		}
	}

	manager.Stop()
	if manager.Started() || manager.Exited() != nil {
		t.Error("after Stop the manager must report not started and a nil Exited")
	}
	for _, line := range manager.StartupTail(0) {
		if strings.Contains(line, "exited unexpectedly") {
			t.Errorf("Stop was reported as an unexpected exit: %q", line)
		}
	}

	manager.Close()
	closed := time.After(5 * time.Second)
	for open := true; open; {
		select {
		case _, open = <-logs:
		case <-closed:
			t.Fatal("subscriber channel was not closed after Close")
		}
	}

	if _, ok := <-manager.SubscribeLogs(context.Background()); ok {
		t.Fatal("expected a closed channel when subscribing after Close")
	}
	if err := manager.Start(filepath.Join(t.TempDir(), "config.toml")); err == nil {
		t.Fatal("Start after Close must fail")
	}
}

// TestProcessLastLinesSurviveExit checks that output written right before
// telemt dies reaches the startup tail: the pipes are read to EOF before Wait
// closes them.
func TestProcessLastLinesSurviveExit(t *testing.T) {
	stderr := make([]string, 0, 301)
	for i := range 300 {
		stderr = append(stderr, fmt.Sprintf("fake line %d", i))
	}
	stderr = append(stderr, "Config error: last words")
	manager := newTestProcessManager(t, fakeTelemt{NoAPI: true, Stderr: stderr, ExitAfter: time.Millisecond, ExitCode: 3})

	if err := manager.Start(filepath.Join(t.TempDir(), "config.toml")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-manager.Exited():
	case <-time.After(10 * time.Second):
		t.Fatal("the fake telemt did not exit")
	}

	tail := manager.StartupTail(3)
	want := []string{"Config error: last words", "fake telemt exiting", "telemt exited unexpectedly: exit status 3"}
	if !slices.Equal(tail, want) {
		t.Errorf("StartupTail(3) = %q, want %q", tail, want)
	}
	if got := len(manager.StartupTail(0)); got != 50 {
		t.Errorf("startup tail holds %d lines, want the ring size 50", got)
	}
}

// TestProcessLongLineKeepsReading checks that an overlong line is cut and
// the lines after it still arrive.
func TestProcessLongLineKeepsReading(t *testing.T) {
	long := strings.Repeat("y", 3*maxTelemtLogLine)
	manager := newTestProcessManager(t, fakeTelemt{NoAPI: true, Stderr: []string{"before", long, "after"}, ExitAfter: time.Millisecond})

	if err := manager.Start(filepath.Join(t.TempDir(), "config.toml")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-manager.Exited():
	case <-time.After(10 * time.Second):
		t.Fatal("the fake telemt did not exit")
	}

	tail := manager.StartupTail(0)
	if len(tail) < 3 || tail[0] != "before" || tail[2] != "after" {
		t.Fatalf("StartupTail = %.80q, want before, the cut line, after", tail)
	}
	if want := strings.Repeat("y", maxTelemtLogLine) + " [truncated]"; tail[1] != want {
		t.Errorf("the long line was kept as %d bytes, want %d", len(tail[1]), len(want))
	}
}

func TestProcessReloadSendsSIGHUP(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "record.json")
	signals := filepath.Join(dir, "signals")
	manager := newTestProcessManager(t, fakeTelemt{NoAPI: true, RecordFile: record, SignalFile: signals})

	if err := manager.Reload(); err == nil {
		t.Error("Reload without a running telemt must fail")
	}
	if err := manager.Start(filepath.Join(dir, "config.toml")); err != nil {
		t.Fatalf("Start: %v", err)
	}
	readFakeTelemtRecord(t, record)

	if err := manager.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	waitFor(t, 10*time.Second, "the fake telemt to receive SIGHUP", func() bool {
		data, _ := os.ReadFile(signals)
		return string(data) == "SIGHUP\n"
	})
	if !manager.Started() {
		t.Error("telemt must keep running after a reload")
	}
}

// TestOrphanCleanupKillsStaleTelemt starts a telemt for the same config path
// outside the manager (left over from a killed node); Start must kill it, and
// must leave a process for a different config path alone.
func TestOrphanCleanupKillsStaleTelemt(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")

	startOutside := func(args ...string) <-chan struct{} {
		t.Helper()
		record := filepath.Join(t.TempDir(), "record.json")
		cmd := exec.Command(writeFakeTelemt(t, fakeTelemt{NoAPI: true, RecordFile: record}), args...)
		if err := cmd.Start(); err != nil {
			t.Fatalf("starting the stray telemt: %v", err)
		}
		done := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(done)
		}()
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			<-done
		})
		readFakeTelemtRecord(t, record)
		return done
	}

	orphanDone := startOutside("run", configPath)
	bystanderDone := startOutside("run", configPath+".old")

	manager := newTestProcessManager(t, fakeTelemt{NoAPI: true})
	if err := manager.Start(configPath); err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case <-orphanDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the orphaned telemt for the same config path is still running")
	}

	select {
	case <-bystanderDone:
		t.Fatal("a process for another config path was killed")
	default:
	}
	if !manager.Started() {
		t.Error("the manager's own telemt is not running")
	}
}
