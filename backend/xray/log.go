package xray

import (
	"bufio"
	"context"
	"io"
	"strings"

	nodeLogger "github.com/pasarguard/node/logger"
)

func isAccessLog(log string) bool {
	if !strings.Contains(log, "from ") || !strings.Contains(log, " email:") {
		return false
	}
	return strings.Contains(log, " accepted tcp:") || strings.Contains(log, " accepted udp:")
}

func (c *Core) detectLogType(log string) {
	if c.logger == nil {
		return
	}

	if isAccessLog(log) {
		c.logger.Log(nodeLogger.LogInfo, log)
		return
	}

	c.logger.Log(nodeLogger.LogError, log)
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
