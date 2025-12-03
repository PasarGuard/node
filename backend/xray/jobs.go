package xray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
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
			// Check for the actual "started" message - this is more reliable
			// Xray outputs: [Warning] core: Xray {version} started
			if strings.Contains(lastLog, "core:") &&
				strings.Contains(lastLog, "Xray "+version) &&
				strings.Contains(lastLog, "started") {
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
	consecutiveFailures := 0
	maxFailures := 3 // Allow a few failures before restarting

	for {
		select {
		case <-baseCtx.Done():
			return
		default:
			ctx, cancel := context.WithTimeout(baseCtx, time.Second*3)
			_, err := x.GetSysStats(ctx)
			cancel()

			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}

				consecutiveFailures++
				// Only restart after multiple consecutive failures
				if consecutiveFailures >= maxFailures {
					log.Printf("xray health check failed %d times, restarting...", consecutiveFailures)
					if err = x.Restart(); err != nil {
						log.Println(err.Error())
					} else {
						log.Println("xray restarted")
						consecutiveFailures = 0 // Reset counter after restart
					}
				}
			} else {
				consecutiveFailures = 0 // Reset on success
			}
		}
		time.Sleep(time.Second * 5)
	}
}
