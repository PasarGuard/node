package xray

import (
	"bufio"
	"context"
	"io"
	"strings"

	nodeLogger "github.com/pasarguard/node/logger"
)

func isAccessLog(log string) bool {
	if !strings.Contains(log, " from ") || !strings.Contains(log, " email:") {
		return false
	}
	return strings.Contains(log, " accepted tcp:") || strings.Contains(log, " accepted udp:")
}

// classifyLogType is the xray access-log heuristic, exactly as it has always
// been. The only change is that the verdict now travels on the record instead
// of being discarded: the file it used to pick and the level it publishes come
// from this one function, so they cannot drift apart (CONTRACT §3.1).
func classifyLogType(log string) nodeLogger.LogLevel {
	if isAccessLog(log) {
		return nodeLogger.LogInfo
	}
	return nodeLogger.LogError
}

func (c *Core) detectLogType(log string) {
	if c.logger == nil {
		return
	}

	// Binds this Logger to the core that owns c.configPath, at most once. The
	// level then travels on the record as well as into the access/error file.
	c.logger.BindOnce(c.configPath)
	c.logger.Log(classifyLogType(log), log)
}

// LogLines is the classified stream, alongside the unchanged Logs() string
// channel: a consumer of the legacy channel sees exactly what it always did.
//
// It binds the Logger to this core on the way past, so a consumer that attaches
// before the first line arrives still gets a live channel rather than nil.
func (c *Core) LogLines() <-chan nodeLogger.LogLine {
	if c.logger == nil {
		return nil
	}
	c.logger.BindOnce(c.configPath)
	return c.logger.LogLines()
}

// LogLines is how the controller reaches a core's classified lines: it holds the
// backend.Backend (the outer Xray), not the inner Core.
func (x *Xray) LogLines() <-chan nodeLogger.LogLine {
	if x == nil || x.core == nil {
		return nil
	}
	return x.core.LogLines()
}

func (c *Core) captureProcessLogs(ctx context.Context, pipe io.Reader) {
	scanner := bufio.NewScanner(pipe)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return // Exit gracefully if stop signal received
		default:
			output := scanner.Text()
			if c.isStartupLogPhase() {
				c.captureStartupLogLine(output)
				continue
			}
			c.captureRuntimeLogLine(output)
		}
	}
}

func (c *Core) recordProcessLog(output string) {
	if c.isStartupLogPhase() {
		c.captureStartupLogLine(output)
		return
	}
	c.captureRuntimeLogLine(output)
}

func (c *Core) captureStartupLogLine(output string) {
	c.RecordStartupLog(output)

	// Non-blocking send: skip if channel is full to prevent deadlock
	select {
	case c.logsChan <- output:
		// Log sent successfully
	default:
		// Channel full, skip this log (prevents blocking xray process)
	}
	// detectLogType binds this Logger to its core and publishes the classified
	// record; the level it computes is the same one the access/error file gets.
	c.detectLogType(output)
}

func (c *Core) captureRuntimeLogLine(output string) {
	c.RecordRuntimeLog(output)
	// Non-blocking send: skip if channel is full to prevent deadlock
	select {
	case c.logsChan <- output:
		// Log sent successfully
	default:
		// Channel full, skip this log (prevents blocking xray process)
	}
	c.detectLogType(output)
}
