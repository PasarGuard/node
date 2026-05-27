package xray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

func (x *Xray) startupLogTailSize() int {
	if x.cfg != nil && x.cfg.StartupLogTailSize > 0 {
		return x.cfg.StartupLogTailSize
	}

	return 200
}

func (x *Xray) extractStartupError() error {
	failure := x.core.LatestStartupFailure()
	if failure == "" {
		return nil
	}

	return fmt.Errorf("failed to start xray: %s", failure)
}

func startupErrorWithTail(core *Core, tailSize int, reason string) error {
	failure := core.LatestStartupFailure()
	if failure != "" {
		return fmt.Errorf("failed to start xray: %s", failure)
	}

	tail := core.StartupLogTail(tailSize)
	if len(tail) == 0 {
		return errors.New(reason)
	}

	return fmt.Errorf("%s; recent xray logs:\n%s", reason, strings.Join(tail, "\n"))
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
			if err := x.extractStartupError(); err != nil {
				return err // Error found in logs
			}

		case <-apiTicker.C:
			ctx, cancel := context.WithTimeout(baseCtx, 1*time.Second)
			_, err := x.GetSysStats(ctx)
			cancel()

			if err == nil {
				x.core.SwitchToRuntimeLogPhase()
				return nil // API check successful
			}

			if err := x.extractStartupError(); err != nil {
				return err // Error found in logs
			}

			// No error in logs, check API
			if !x.core.Started() {
				return startupErrorWithTail(x.core, x.startupLogTailSize(), "xray process stopped before API became ready")
			}
		}
	}
}

func (x *Xray) checkXrayHealth(baseCtx context.Context) {
	consecutiveFailures := 0
	maxFailures := 10 // Give Xray API time to recover under load before restarting.
	checkInterval := 2 * time.Second

	restart := func(reason string) {
		log.Println(reason)
		if tail := x.core.RuntimeLogTail(10); len(tail) > 0 {
			log.Printf("last %d xray log lines before restart:\n%s", len(tail), strings.Join(tail, "\n"))
		}
		if err := x.Restart(); err != nil {
			log.Println(err.Error())
		} else {
			log.Println("xray restarted")
			consecutiveFailures = 0
		}
	}

	for {
		select {
		case <-baseCtx.Done():
			return
		default:
			if x.core.Restarting() {
				consecutiveFailures = 0
				time.Sleep(checkInterval)
				continue
			}

			ctx, cancel := context.WithTimeout(baseCtx, 3*time.Second)
			_, err := x.GetSysStats(ctx)
			cancel()

			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}

				consecutiveFailures++
				log.Printf("xray health check failure %d/%d: %v", consecutiveFailures, maxFailures, err)

				if !x.core.Started() {
					restart("xray process is not running, restarting...")
				} else if consecutiveFailures >= maxFailures {
					restart(fmt.Sprintf("xray health check failed %d times, restarting...", consecutiveFailures))
				}
			} else {
				consecutiveFailures = 0 // Reset on success
			}
		}
		time.Sleep(checkInterval)
	}
}
