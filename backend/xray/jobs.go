package xray

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	nodeLogger "github.com/m03ed/gozargah-node/logger"
)

func (x *Xray) checkXrayStatus() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	
	core := x.core
	logChan := core.Logs()
	version := core.Version()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// Precompile regex for better performance
	logRegex := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^]]+)] (.+)$`)

	for {
		select {
		case lastLog := <-logChan:
			if strings.Contains(lastLog, "Xray "+version+" started") {
				return nil
			}

			// Check for failure patterns
			matches := logRegex.FindStringSubmatch(lastLog)
			if len(matches) > 3 {
				// Check both error level and message content
				if matches[2] == "Error" || strings.Contains(matches[3], "Failed to start") {
					return fmt.Errorf("failed to start xray: %s", matches[3])
				}
			} else {
				// Fallback check if log format doesn't match
				if strings.Contains(lastLog, "Failed to start") {
					return fmt.Errorf("failed to start xray: %s", lastLog)
				}
			}

		case <-ctx.Done():
			return errors.New("failed to start xray: context timeout")
		}
	}
}

func (x *Xray) checkXrayHealth(baseCtx context.Context) {
	for {
		select {
		case <-baseCtx.Done():
			return
		default:
			ctx, cancel := context.WithTimeout(baseCtx, time.Second*3)
			_, err := x.GetSysStats(ctx)
			cancel() // Always call cancel to avoid context leak

			if err != nil {
				if errors.Is(err, context.Canceled) {
					// Context was canceled due to x.ctx cancellation
					return // Exit gracefully
				}

				// Handle other errors by attempting restart
				if err = x.Restart(); err != nil {
					nodeLogger.Log(nodeLogger.LogError, err.Error())
				} else {
					nodeLogger.Log(nodeLogger.LogInfo, "xray restarted")
				}
			}
		}
		time.Sleep(time.Second * 5)
	}
}
