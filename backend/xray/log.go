package xray

import (
	"bufio"
	"context"
	"io"

	nodeLogger "github.com/pasarguard/node/logger"
)

func (c *Core) captureProcessLogs(ctx context.Context, pipe io.Reader, level nodeLogger.LogLevel) {
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return // Exit gracefully if stop signal received
		default:
			output := scanner.Text()
			c.logsChan <- output
			if c.logger != nil {
				c.logger.Log(level, output)
			}
		}
	}
}
