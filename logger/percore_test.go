package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestCoreLogFileName: core_id 0 is the node's own logs and keeps the legacy
// node.log name, so a single-core node is byte-identical to today (CONTRACT §3.1).
func TestCoreLogFileName(t *testing.T) {
	if got := CoreLogFileName(0); got != "node.log" {
		t.Errorf("CoreLogFileName(0) = %q, want node.log", got)
	}
	for id, want := range map[uint64]string{1: "core-1.log", 2: "core-2.log", 17: "core-17.log"} {
		if got := CoreLogFileName(id); got != want {
			t.Errorf("CoreLogFileName(%d) = %q, want %q", id, got, want)
		}
	}
}

// TestPerCoreFilesNeverMix is the negative assertion that matters: a line
// emitted by core 2 must never appear in core 1's file.
func TestPerCoreFilesNeverMix(t *testing.T) {
	dir := t.TempDir()
	files := NewPerCoreFiles(dir)
	defer files.Close()

	files.SetClock(func() time.Time { return time.UnixMilli(1700000000000) })

	for i := range 50 {
		files.Write(1, LogLine{Detail: "core-one-line", Level: LogInfo})
		files.Write(2, LogLine{Detail: "core-two-line", Level: LogError})
		_ = i
	}

	one := readFile(t, filepath.Join(dir, "core-1.log"))
	two := readFile(t, filepath.Join(dir, "core-2.log"))

	if !strings.Contains(one, "core-one-line") {
		t.Error("core-1.log is missing core 1's own line")
	}
	if strings.Contains(one, "core-two-line") {
		t.Error("core-2.log content leaked into core-1.log")
	}
	if !strings.Contains(two, "core-two-line") {
		t.Error("core-2.log is missing core 2's own line")
	}
	if strings.Contains(two, "core-one-line") {
		t.Error("core-1.log content leaked into core-2.log")
	}

	if got, want := strings.Count(one, "core-one-line"), 50; got != want {
		t.Errorf("core-1.log has %d lines, want %d", got, want)
	}
	if got, want := strings.Count(two, "core-two-line"), 50; got != want {
		t.Errorf("core-2.log has %d lines, want %d", got, want)
	}
}

// TestPerCoreFilesCarryLevelAndTimestamp: the file record is the same record the
// wire carries, so a file read after the panel is down still has the level.
func TestPerCoreFilesCarryLevelAndTimestamp(t *testing.T) {
	dir := t.TempDir()
	files := NewPerCoreFiles(dir)
	defer files.Close()

	files.SetClock(func() time.Time { return time.UnixMilli(1700000000123) })
	files.Write(3, LogLine{Detail: "boom", Level: LogCritical})

	got := strings.TrimSpace(readFile(t, filepath.Join(dir, "core-3.log")))
	want := "1700000000123 Critical boom"
	if got != want {
		t.Errorf("core-3.log line = %q, want %q", got, want)
	}
}

// TestCoreLogLocation: the per-core directory config.CoreConfigPath already
// builds is what identifies a core, so no constructor has to say which core it
// is being built for.
func TestCoreLogLocation(t *testing.T) {
	root := filepath.Join("var", "lib", "pg-node", "generated")

	id, dir, ok := CoreLogLocation(filepath.Join(root, "core-1"))
	if !ok || id != 1 {
		t.Fatalf("core-1: id=%d ok=%v, want 1/true", id, ok)
	}
	if dir != root {
		t.Errorf("log dir = %q, want %q", dir, root)
	}

	if id, _, ok := CoreLogLocation(filepath.Join(root, "core-2")); !ok || id != 2 {
		t.Errorf("core-2: id=%d ok=%v, want 2/true", id, ok)
	}

	// Not a per-core directory: no binding, so a Logger built against it keeps
	// writing nothing extra rather than guessing.
	if _, _, ok := CoreLogLocation(root); ok {
		t.Error("a bare generated path must not bind to a core")
	}
	if _, _, ok := CoreLogLocation(filepath.Join(root, "core-0")); ok {
		t.Error("core-0 must not bind: core_id 0 is the node's own logs")
	}
	if _, _, ok := CoreLogLocation(filepath.Join(root, "core-x")); ok {
		t.Error("a non-numeric core dir must not bind")
	}
}

// TestLoggerBindsToItsOwnFile: the binding is derived from the config dir the
// core was given, so two cores writing at once land in two different files.
func TestLoggerBindsToItsOwnFile(t *testing.T) {
	root := t.TempDir()

	l1 := New(false)
	l1.BindOnce(filepath.Join(root, "core-1"))
	l2 := New(false)
	l2.BindOnce(filepath.Join(root, "core-2"))
	defer l1.Close()
	defer l2.Close()

	l1.Log(LogInfo, "hello-from-one")
	l2.Log(LogError, "hello-from-two")

	if l1.LogLines() == nil || l2.LogLines() == nil {
		t.Fatal("a bound Logger must expose a classified channel")
	}
	if l1.LogLines() == l2.LogLines() {
		t.Error("two cores share one classified channel; lines could be attributed to the wrong core")
	}

	one := readFile(t, filepath.Join(root, "core-1.log"))
	two := readFile(t, filepath.Join(root, "core-2.log"))
	if !strings.Contains(one, "hello-from-one") || strings.Contains(one, "hello-from-two") {
		t.Errorf("core-1.log content is wrong:\n%s", one)
	}
	if !strings.Contains(two, "hello-from-two") || strings.Contains(two, "hello-from-one") {
		t.Errorf("core-2.log content is wrong:\n%s", two)
	}
}

// TestUnboundLoggerIsInert: a Logger that never saw a core dir keeps every old
// behaviour and simply publishes nowhere.
func TestUnboundLoggerIsInert(t *testing.T) {
	l := New(false)
	l.Log(LogInfo, "nowhere")

	if l.LogLines() != nil {
		t.Error("an unbound Logger must not expose a channel")
	}
}

// TestLinesPublishedBeforeBindSurvive is the regression for the defect a live
// three-core gate found: a core that was actively serving traffic contributed
// ZERO log records, because the channel was created on the first line and
// GetLogs snapshots its sources once, so everything logged before the stream
// attached was gone. A core's records must exist from the moment it starts.
func TestLinesPublishedBeforeBindSurvive(t *testing.T) {
	root := t.TempDir()

	// A Logger that has not seen its core directory yet: it publishes, and has
	// no channel to publish to. This is the state every core is in between
	// construction and its first BindOnce.
	l := New(false)

	l.Log(LogInfo, "before-bind-1")
	l.Log(LogError, "before-bind-2")

	if l.LogLines() != nil {
		t.Fatal("an unbound Logger must not expose a channel")
	}

	// Now it learns which core it belongs to — as a core does when its config
	// directory is handed to it.
	l.BindOnce(filepath.Join(root, "core-3"))
	defer l.Close()

	ch := l.LogLines()
	if ch == nil {
		t.Fatal("a bound Logger must expose a channel")
	}

	// Both lines, in order. This is the whole assertion: a consumer that
	// attaches now must still see what the core logged before it attached.
	for _, want := range []string{"before-bind-1", "before-bind-2"} {
		select {
		case got := <-ch:
			if got.Detail != want {
				t.Fatalf("channel delivered %q, want %q (backfill must preserve order)", got.Detail, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("channel delivered nothing for %q; lines published before bind were lost", want)
		}
	}
}

// TestBackfillIsBounded: the fix must not be "buffer without limit". The ring
// keeps the same DefaultLogBuffer bound the live channel already had, so the
// worst case is identical to the worst case a slow consumer already had.
func TestBackfillIsBounded(t *testing.T) {
	l := New(false)

	total := DefaultLogBuffer * 2
	for i := range total {
		l.Publish(LogLine{Detail: fmt.Sprintf("line-%d", i), Level: LogInfo})
	}
	if len(l.backfill) > DefaultLogBuffer {
		t.Fatalf("an unbound Logger kept %d lines, want at most %d: the backfill must be bounded",
			len(l.backfill), DefaultLogBuffer)
	}

	l.BindOnce(filepath.Join(t.TempDir(), "core-1"))
	defer l.Close()

	ch := l.LogLines()
	// The newest DefaultLogBuffer lines survive; the oldest were dropped. Read
	// the first one back: it must NOT be line-0.
	select {
	case got := <-ch:
		if got.Detail == "line-0" {
			t.Fatal("the backfill kept the oldest lines; a bounded ring must keep the most recent")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bounded backfill replayed nothing")
	}
}

// TestUnboundLoggerStillWritesNothingElse: the backfill is only reachable
// through BindOnce, so a Logger that never binds still publishes nowhere and
// still exposes no channel — the behaviour a non-core caller relies on.
func TestUnboundLoggerStillWritesNothingElse(t *testing.T) {
	l := New(false)
	for i := range 5 {
		l.Publish(LogLine{Detail: fmt.Sprintf("nowhere-%d", i), Level: LogInfo})
	}
	if l.LogLines() != nil {
		t.Error("an unbound Logger must not expose a channel")
	}
}

// TestPublishNeverBlocks: a consumer that stopped reading must not wedge the
// producer. This is the same property the legacy non-blocking send guarantees.
func TestPublishNeverBlocks(t *testing.T) {
	root := t.TempDir()
	l := New(false)
	l.BindOnce(filepath.Join(root, "core-1"))
	defer l.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 10_000 {
			l.Publish(LogLine{Detail: "flood", Level: LogInfo})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a full log channel blocked the producer")
	}
	l.Close()

	// The file still got every line: the file write does not share the channel's
	// capacity.
	got := strings.Count(readFile(t, filepath.Join(root, "core-1.log")), "flood")
	if got != 10_000 {
		t.Errorf("core-1.log has %d lines, want 10000", got)
	}
}
