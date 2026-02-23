package xray

import (
	"strings"
	"testing"
)

func TestStartupLogRingTail(t *testing.T) {
	ring := newStartupLogRing(3)
	ring.add("l1")
	ring.add("l2")
	ring.add("l3")
	ring.add("l4")

	tail := ring.tail(3)
	want := []string{"l2", "l3", "l4"}
	if len(tail) != len(want) {
		t.Fatalf("unexpected tail length: got %d, want %d", len(tail), len(want))
	}
	for i := range want {
		if tail[i] != want[i] {
			t.Fatalf("unexpected tail[%d]: got %q, want %q", i, tail[i], want[i])
		}
	}

	tail = ring.tail(2)
	want = []string{"l3", "l4"}
	for i := range want {
		if tail[i] != want[i] {
			t.Fatalf("unexpected short tail[%d]: got %q, want %q", i, tail[i], want[i])
		}
	}
}

func TestRecordStartupLogCapturesFailure(t *testing.T) {
	core := &Core{}
	core.EnableStartupDiagnostics(5)

	core.RecordStartupLog("normal startup log")
	if got := core.LatestStartupFailure(); got != "" {
		t.Fatalf("unexpected failure marker: %q", got)
	}

	failureLine := "2026/02/21 [Error] Failed to start app/proxyman"
	core.RecordStartupLog(failureLine)

	if got := core.LatestStartupFailure(); got != failureLine {
		t.Fatalf("unexpected startup failure line: got %q, want %q", got, failureLine)
	}
}

func TestStartupErrorWithTailFallback(t *testing.T) {
	core := &Core{}
	core.EnableStartupDiagnostics(5)
	core.RecordStartupLog("line1")
	core.RecordStartupLog("line2")
	core.RecordStartupLog("line3")

	err := startupErrorWithTail(core, 2, "xray process stopped before API became ready")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	msg := err.Error()
	if !strings.Contains(msg, "xray process stopped before API became ready") {
		t.Fatalf("error does not include reason: %q", msg)
	}
	if strings.Contains(msg, "line1") {
		t.Fatalf("error should not include dropped line: %q", msg)
	}
	if !strings.Contains(msg, "line2") || !strings.Contains(msg, "line3") {
		t.Fatalf("error should include recent tail lines: %q", msg)
	}
}

func TestStartupErrorWithTailPrefersMatchedFailure(t *testing.T) {
	core := &Core{}
	core.EnableStartupDiagnostics(5)
	core.RecordStartupLog("first line")
	core.RecordStartupLog("2026/02/21 [Error] Failed to listen TCP on 127.0.0.1:443")
	core.RecordStartupLog("third line")

	err := startupErrorWithTail(core, 3, "xray process stopped before API became ready")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	msg := err.Error()
	if !strings.Contains(msg, "failed to start xray:") {
		t.Fatalf("expected startup failure prefix: %q", msg)
	}
	if strings.Contains(msg, "recent xray logs:") {
		t.Fatalf("expected matched failure to be returned directly, got tail: %q", msg)
	}
}

func TestIsStartupFailureLog(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{line: "2026/02/21 [Error] Failed to start app/proxyman", want: true},
		{line: "panic: runtime error", want: true},
		{line: "2026/02/23 07:13:42.313765 from 5.250.114.189:0 rejected proxy/vless/encoding: invalid request user id: 1ffca7fc-4bb6-4701-9cfc-b046a28c569a", want: false},
		{line: "accepted tcp:www.gstatic.com:443 [TAG -> DIRECT] email: a@b.com", want: false},
		{line: "2026/02/21 [Info] app/stats: create new counter", want: false},
	}

	for _, tt := range tests {
		if got := isStartupFailureLog(tt.line); got != tt.want {
			t.Fatalf("isStartupFailureLog(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestDisableStartupDiagnosticsStopsRecordingAndClearsState(t *testing.T) {
	core := &Core{}
	core.EnableStartupDiagnostics(3)
	core.RecordStartupLog("line1")
	core.RecordStartupLog("failed to start config")

	core.DisableStartupDiagnostics()

	if got := core.LatestStartupFailure(); got != "" {
		t.Fatalf("expected cleared failure after disable, got %q", got)
	}
	if tail := core.StartupLogTail(3); len(tail) != 0 {
		t.Fatalf("expected empty tail after disable, got %v", tail)
	}

	core.RecordStartupLog("failed to start again")
	if got := core.LatestStartupFailure(); got != "" {
		t.Fatalf("expected no recording while disabled, got %q", got)
	}
}

func TestSwitchToRuntimeLogPhaseDisablesStartupDiagnostics(t *testing.T) {
	core := &Core{}
	core.EnableStartupDiagnostics(3)
	core.setStartupLogPhase()
	core.RecordStartupLog("failed to start config")

	if !core.isStartupLogPhase() {
		t.Fatal("expected startup phase before switch")
	}

	core.SwitchToRuntimeLogPhase()

	if core.isStartupLogPhase() {
		t.Fatal("expected runtime phase after switch")
	}
	if got := core.LatestStartupFailure(); got != "" {
		t.Fatalf("expected cleared failure after runtime switch, got %q", got)
	}
	if tail := core.StartupLogTail(3); len(tail) != 0 {
		t.Fatalf("expected empty startup tail after runtime switch, got %v", tail)
	}

	core.RecordStartupLog("failed to start again")
	if got := core.LatestStartupFailure(); got != "" {
		t.Fatalf("expected no startup recording in runtime phase, got %q", got)
	}
}
