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

	return fmt.Errorf("%s; no fatal xray startup log was detected. Recent xray logs:\n%s", reason, strings.Join(tail, "\n"))
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
				reason := "xray process stopped before API became ready"
				if x.core.Stopping() {
					reason = "xray startup was interrupted by a stop/restart request before API became ready"
				}
				return startupErrorWithTail(x.core, x.startupLogTailSize(), reason)
			}
		}
	}
}

func (x *Xray) checkXrayHealth(baseCtx context.Context) {
	consecutiveFailures := 0
	maxFailures := 10 // Give Xray API time to recover under load before restarting.
	checkInterval := 2 * time.Second

	probe := func() error {
		ctx, cancel := context.WithTimeout(baseCtx, 3*time.Second)
		defer cancel()
		_, err := x.GetSysStats(ctx)
		return err
	}

	restart := func(reason string) {
		// Lock order: syncMu, then mu, then core.mu, as in the user syncs.
		// syncMu keeps user syncs off the new core until its API answers.
		x.syncMu.Lock()
		defer x.syncMu.Unlock()

		// A full sync may have replaced the core while this restart waited
		// for syncMu: leave a core that answers alone.
		if x.Started() && probe() == nil {
			log.Println("xray answers again, health restart skipped")
			consecutiveFailures = 0
			return
		}

		log.Println(reason)
		if tail := x.core.RuntimeLogTail(10); len(tail) > 0 {
			log.Printf("last %d xray log lines before restart:\n%s", len(tail), strings.Join(tail, "\n"))
		}
		// Count from zero for the new core even if it is not ready yet, so a
		// core still booting after restartReadyTimeout gets maxFailures more
		// probes before the next restart.
		consecutiveFailures = 0
		if err := x.restartLocked(baseCtx); err != nil {
			log.Println(err.Error())
		} else {
			log.Println("xray restarted")
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

			if err := probe(); err != nil {
				// Shutdown cancels baseCtx. Check it directly: GetSysStats
				// re-wraps the cancelled call as a gRPC status, which
				// errors.Is(err, context.Canceled) does not match.
				if baseCtx.Err() != nil {
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
