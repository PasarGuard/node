package xray

import (
	"bufio"
	"context"
	"io"
	"regexp"
	"sync"

	nodeLogger "github.com/pasarguard/node/logger"
)

var (
	accessLogPattern = regexp.MustCompile(`from .+:\d+ accepted (tcp|udp):.+:\d+ \[.+\] email: .+`)
	bufPool          = sync.Pool{
		New: func() any {
			buf := make([]byte, 64*1024)
			return &buf
		},
	}
)

func (c *Core) detectLogType(log string) {
	if c.logger == nil {
		return
	}

	if accessLogPattern.MatchString(log) {
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
			return
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

	select {
	case c.logsChan <- output:
	default:
	}
	c.detectLogType(output)
}

func (c *Core) captureRuntimeLogLine(output string) {
	c.RecordRuntimeLog(output)
	select {
	case c.logsChan <- output:
	default:
	}
	c.detectLogType(output)
}
