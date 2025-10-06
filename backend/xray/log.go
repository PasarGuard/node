package xray

import (
	"bufio"
	"context"
	"io"
	"regexp"
	"strings"

	nodeLogger "github.com/pasarguard/node/logger"
)

var (
	re *regexp.Regexp
)

func init() {
	pattern := `^(\d{4}/\d{2}/\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?) (\[.*?\]) (.*)$`

	// Compile the regex
	re = regexp.MustCompile(pattern)
}

func (c *Core) detectLogType(newLog string) {
	if c.logger == nil {
		return
	}

	level := nodeLogger.LogDebug

	// Find the matches to detect log level
	matches := re.FindStringSubmatch(newLog)
	if len(matches) > 3 {
		detectedLevel := strings.Trim(matches[3], "[]")
		// Map xray log levels to our logger levels
		switch strings.ToLower(detectedLevel) {
		case "error":
			level = nodeLogger.LogError
		case "warning":
			level = nodeLogger.LogWarning
		case "info":
			level = nodeLogger.LogInfo
		case "debug":
			level = nodeLogger.LogDebug
		default:
			level = nodeLogger.LogDebug
		}
	}

	// Log the complete original message
	c.logger.Log(level, newLog)
}

func (c *Core) captureProcessLogs(ctx context.Context, pipe io.Reader) {
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return // Exit gracefully if stop signal received
		default:
			output := scanner.Text()
			c.logsChan <- output
			c.detectLogType(output)
		}
	}
}
