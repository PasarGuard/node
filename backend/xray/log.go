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
	pattern := `^(\d{4}/\d{2}/\d{2}) (\d{2}:\d{2}:\d{2}) (\[.*?\]) (.*)$`

	// Compile the regex
	re = regexp.MustCompile(pattern)
}

func (c *Core) detectLogType(newLog string) {
	message := ""
	level := ""

	// Find the matches
	matches := re.FindStringSubmatch(newLog)
	if len(matches) > 3 {
		level = strings.Trim(matches[3], "[]")
		message = matches[4]
	} else {
		message = newLog
	}

	if level == "" {
		level = "Debug"
	}

	nodeLogger.Log(level, message)
}

func (c *Core) captureProcessLogs(ctx context.Context, pipe io.Reader) {
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return // Exit gracefully if stop signal received
		default:
			output := scanner.Text()
			c.detectLogType(output)
			c.logsChan <- output
		}
	}
}
