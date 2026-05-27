package xray

import (
	"strings"
	"sync/atomic"
)

const (
	logPhaseRuntime uint32 = iota
	logPhaseStartup
)

type startupLogRing struct {
	lines []string
	next  int
	full  bool
}

func newStartupLogRing(size int) *startupLogRing {
	if size <= 0 {
		size = 1
	}

	return &startupLogRing{
		lines: make([]string, size),
	}
}

func (r *startupLogRing) reset() {
	r.next = 0
	r.full = false
	for i := range r.lines {
		r.lines[i] = ""
	}
}

func (r *startupLogRing) add(line string) {
	if len(r.lines) == 0 {
		return
	}

	r.lines[r.next] = line
	r.next = (r.next + 1) % len(r.lines)
	if r.next == 0 {
		r.full = true
	}
}

func (r *startupLogRing) tail(n int) []string {
	count := r.next
	if r.full {
		count = len(r.lines)
	}
	if count == 0 {
		return nil
	}

	if n <= 0 || n > count {
		n = count
	}

	oldest := 0
	if r.full {
		oldest = r.next
	}

	start := count - n
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		idx := (oldest + start + i) % len(r.lines)
		out = append(out, r.lines[idx])
	}

	return out
}

func (c *Core) ClearStartupDiagnostics() {
	c.startupMu.Lock()
	defer c.startupMu.Unlock()

	c.startupFailure = ""
	if c.startupLogs != nil {
		c.startupLogs.reset()
	}
}

func (c *Core) EnableStartupDiagnostics(tailSize int) {
	c.startupMu.Lock()
	defer c.startupMu.Unlock()

	if tailSize <= 0 {
		tailSize = c.startupLogSize
	}
	if tailSize <= 0 {
		tailSize = 200
	}

	c.startupLogSize = tailSize
	if c.startupLogs == nil || len(c.startupLogs.lines) != tailSize {
		c.startupLogs = newStartupLogRing(tailSize)
	} else {
		c.startupLogs.reset()
	}

	c.startupFailure = ""
	c.startupDiagnosticsEnabled = true
}

func (c *Core) DisableStartupDiagnostics() {
	c.startupMu.Lock()
	defer c.startupMu.Unlock()

	c.startupDiagnosticsEnabled = false
	c.startupFailure = ""
	c.startupLogs = nil
}

func (c *Core) setStartupLogPhase() {
	atomic.StoreUint32(&c.logPhase, logPhaseStartup)
}

func (c *Core) SwitchToRuntimeLogPhase() {
	atomic.StoreUint32(&c.logPhase, logPhaseRuntime)
	c.DisableStartupDiagnostics()
}

func (c *Core) isStartupLogPhase() bool {
	return atomic.LoadUint32(&c.logPhase) == logPhaseStartup
}

func (c *Core) RecordStartupLog(line string) {
	c.startupMu.Lock()
	defer c.startupMu.Unlock()

	if !c.startupDiagnosticsEnabled {
		return
	}

	if c.startupLogs != nil {
		c.startupLogs.add(line)
	}
	if isStartupFailureLog(line) {
		c.startupFailure = line
	}
}

func (c *Core) LatestStartupFailure() string {
	c.startupMu.RLock()
	defer c.startupMu.RUnlock()

	if !c.startupDiagnosticsEnabled {
		return ""
	}

	return c.startupFailure
}

func (c *Core) StartupLogTail(n int) []string {
	c.startupMu.RLock()
	defer c.startupMu.RUnlock()

	if !c.startupDiagnosticsEnabled || c.startupLogs == nil {
		return nil
	}

	return c.startupLogs.tail(n)
}

func (c *Core) RecordRuntimeLog(line string) {
	c.runtimeMu.Lock()
	defer c.runtimeMu.Unlock()
	c.runtimeLogs.add(line)
}

func (c *Core) RuntimeLogTail(n int) []string {
	c.runtimeMu.RLock()
	defer c.runtimeMu.RUnlock()
	if c.runtimeLogs == nil {
		return nil
	}
	return c.runtimeLogs.tail(n)
}

func isStartupFailureLog(line string) bool {
	lower := strings.ToLower(line)

	// Client authentication/rejection logs can include "invalid" and are not startup-fatal.
	if strings.Contains(lower, "invalid request user id") || strings.Contains(lower, "rejected proxy/") {
		return false
	}

	keywords := [...]string{
		"failed to start",
		"panic",
		"fatal",
		"permission denied",
		"no such file or directory",
		"cannot find",
		"failed to open",
		"failed to load",
		"failed to listen",
	}

	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}

	return false
}
