package xray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

func (x *Xray) extractError(ctx context.Context) error {
	logChan := x.core.Logs()

	for {
		select {
		case <-ctx.Done():
			return nil

		case log := <-logChan:
			if strings.Contains(log, "Failed to start") {
				return fmt.Errorf("failed to start xray: %s", log)
			}
		}
	}
}

func (x *Xray) checkXrayStatus(baseCtx context.Context) error {
	apiTicker := time.NewTicker(1 * time.Second)
	defer apiTicker.Stop()
	errorTicker := time.NewTicker(2 * time.Second)
	defer errorTicker.Stop()

	for {
		select {
		case <-baseCtx.Done():
			return errors.New("context cancelled")

		case <-errorTicker.C:
			// Check logs every 3 seconds with 1 second timeout
			ctx, cancel := context.WithTimeout(baseCtx, 1*time.Second)
			err := x.extractError(ctx)
			cancel()

			if err != nil {
				return err // Error found in logs
			}

		case <-apiTicker.C:
			ctx, cancel := context.WithTimeout(baseCtx, 400*time.Millisecond)
			_, err := x.GetSysStats(ctx)
			cancel()

			if err == nil {
				return nil // API check successful
			}

			// No error in logs, check API
			if !x.core.Started() {
				return errors.New("xray process stopped")
			}
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
