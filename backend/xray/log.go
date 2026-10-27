package xray

import (
	"bufio"
	"context"
	"io"
	"strings"
	"sync"

	nodeLogger "github.com/pasarguard/node/logger"
)

var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

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
	bufp := bufPool.Get().(*[]byte)
	scanner.Buffer(*bufp, 1024*1024)
	defer bufPool.Put(bufp)

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
	if c.logs != nil {
		c.logs.Publish(output)
	}
	c.detectLogType(output)
}

func (c *Core) captureRuntimeLogLine(output string) {
	c.RecordRuntimeLog(output)
	if c.logs != nil {
		c.logs.Publish(output)
	}
	c.detectLogType(output)
}
