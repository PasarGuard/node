package mtproto

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	// markerPollInterval is how often the node checks whether telemt loaded
	// a rendered config.
	markerPollInterval = 200 * time.Millisecond
	// markerUnreachablePolls is how many polls in a row must get no answer
	// before telemt counts as unreachable and is restarted, unless it exited.
	markerUnreachablePolls = 3
)

// telemtSignalGrace is how long after telemt's API first answers the node
// does not send SIGHUP. telemt's config watcher installs the SIGHUP handler
// only after the API is up and the watcher has read the config and set up
// its watches, and a SIGHUP before that ends telemt. The watcher loads most
// renders of that time on its own, but misses one written while it sets up.
// It is a variable so tests can lower it.
var telemtSignalGrace = 5 * time.Second

// markerConfirmTimeout bounds the wait for telemt to load a rendered config;
// a config it did not load by then counts as rejected. It is a variable so
// tests can lower it.
var markerConfirmTimeout = 30 * time.Second

// errReloadRejected marks a rendered config telemt did not load. telemt
// keeps running the config it had.
var errReloadRejected = errors.New("telemt did not load the new config")

// reloadLocked makes the running telemt hot-reload the rendered config and
// waits until the render's marker user is in telemt's running config.
// telemt's config watcher sees the file change, and SIGHUP makes sure once
// telemtSignalGrace allows it (see waitForMarker). A hot reload replaces
// only the users that changed; an API reload would cut every session. Only
// an API that stays unreachable, or a telemt that exited or cannot be
// signalled, restarts telemt, on the rendered config; a rejected config
// never does. Requires syncMu.
func (m *MTProto) reloadLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Should telemt not handle the signal after all, SIGHUP ends it and the
	// restart below recovers it.
	err := m.waitForMarker(ctx, m.marker.Username, m.healthyAt.Add(telemtSignalGrace))
	switch {
	case err == nil || errors.Is(err, errClosed) || errors.Is(err, errReloadRejected):
		return err
	case ctx.Err() != nil:
		return fmt.Errorf("telemt reload not confirmed: %w", ctx.Err())
	}

	log.Printf("telemt did not answer a reload, restarting it: %v", err)
	m.process.Stop()
	// telemt is down now: start it again even if ctx ends.
	if restartErr := m.startLocked(context.WithoutCancel(ctx)); restartErr != nil {
		return fmt.Errorf("telemt reload failed: %w (restart failed: %v)", err, restartErr)
	}
	return nil
}

// signalReloadLocked sends telemt SIGHUP, unless its API first answered
// less than telemtSignalGrace ago; telemt's config watcher sees the change
// then. Requires syncMu.
func (m *MTProto) signalReloadLocked() error {
	if time.Since(m.healthyAt) < telemtSignalGrace {
		return nil
	}
	return m.process.Reload()
}

// waitForMarker polls GET /v1/users until telemt's running config has the
// marker user, for up to markerConfirmTimeout, and sends telemt SIGHUP once
// signalAt has passed: at once in steady state, or when telemtSignalGrace
// ends if the watcher has not loaded the render by then. It returns an
// errReloadRejected error when telemt cannot read the rendered file or the
// time is up, errClosed on Shutdown, ctx's error when ctx ends, and the
// signal or request error when telemt cannot be signalled, the API stays
// unreachable or telemt exited.
func (m *MTProto) waitForMarker(ctx context.Context, marker string, signalAt time.Time) error {
	waitCtx, cancel := context.WithTimeout(ctx, markerConfirmTimeout)
	defer cancel()
	stop := context.AfterFunc(m.lifetime, cancel)
	defer stop()

	exited := m.process.Exited()
	ticker := time.NewTicker(markerPollInterval)
	defer ticker.Stop()

	signalled := false
	unanswered := 0
	for {
		if !signalled && !time.Now().Before(signalAt) {
			signalled = true
			if err := m.process.Reload(); err != nil {
				return err
			}
		}

		users, err := m.apiClient.ListUsers(waitCtx)
		var apiErr *apiStatusError
		switch {
		case err == nil:
			unanswered = 0
			if userInRuntime(users, marker) {
				return nil
			}
		case errors.As(err, &apiErr):
			unanswered = 0
			// telemt reads the config file for this list: it cannot read or
			// parse the render.
			if cannotLoadConfig(apiErr) {
				return fmt.Errorf("%w: %s", errReloadRejected, apiErr.Message)
			}
		case waitCtx.Err() == nil:
			unanswered++
			if unanswered >= markerUnreachablePolls || isClosed(exited) {
				return fmt.Errorf("telemt API unreachable: %w", err)
			}
		}

		select {
		case <-waitCtx.Done():
			switch {
			case m.lifetime.Err() != nil:
				return errClosed
			case ctx.Err() != nil:
				return ctx.Err()
			default:
				return m.reloadRejectedError()
			}
		case <-ticker.C:
		}
	}
}

// reloadRejectedError reports a config telemt did not load in time, with
// its last output, which carries the reason.
func (m *MTProto) reloadRejectedError() error {
	tail := m.process.StartupTail(telemtCrashTailSize)
	if len(tail) == 0 {
		return fmt.Errorf("%w within %s", errReloadRejected, markerConfirmTimeout)
	}
	return fmt.Errorf("%w within %s; recent telemt output:\n%s", errReloadRejected, markerConfirmTimeout, strings.Join(tail, "\n"))
}

// cannotLoadConfig reports whether telemt answered that it cannot use its
// config file: it reads the file and its includes first ("failed to read
// config graph", which also enforces telemt's 8 MiB limit per file), then
// parses them ("failed to load config").
func cannotLoadConfig(apiErr *apiStatusError) bool {
	if apiErr.StatusCode < http.StatusInternalServerError {
		return false
	}
	return strings.Contains(apiErr.Message, "failed to read config graph") ||
		strings.Contains(apiErr.Message, "failed to load config")
}

func userInRuntime(users []telemtUserInfo, username string) bool {
	for _, user := range users {
		if user.Username == username {
			return user.InRuntime
		}
	}
	return false
}

// isClosed reports whether ch is closed; a nil ch never is.
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
