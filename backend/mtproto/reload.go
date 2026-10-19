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

// markerConfirmTimeout bounds the wait for telemt to load a rendered config;
// a config it did not load by then counts as rejected. It is a variable so
// tests can lower it.
var markerConfirmTimeout = 30 * time.Second

// errReloadRejected marks a rendered config telemt did not load. telemt
// keeps running the config it had.
var errReloadRejected = errors.New("telemt did not load the new config")

// reloadLocked makes the running telemt hot-reload the rendered config:
// SIGHUP (telemt's config watcher also sees the file change), then a wait
// until the render's marker user is in telemt's running config. A hot reload
// replaces only the users that changed; an API reload would cut every
// session. Only an API that stays unreachable, or a telemt that exited or
// cannot be signalled, restarts telemt, on the rendered config; a rejected
// config never does. Requires syncMu.
func (m *MTProto) reloadLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// telemt installs its SIGHUP handler in its config watcher, which starts
	// before the API the node waited for at startup, so a healthy telemt
	// handles the signal. Should one not, SIGHUP ends it and the restart
	// below recovers it.
	err := m.process.Reload()
	if err == nil {
		err = m.waitForMarker(ctx, m.marker.Username)
	}
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

// waitForMarker polls GET /v1/users until telemt's running config has the
// marker user, for up to markerConfirmTimeout. It returns an errReloadRejected
// error when telemt cannot read the rendered file or the time is up,
// errClosed on Shutdown, ctx's error when ctx ends, and the request error
// when the API stays unreachable or telemt exited.
func (m *MTProto) waitForMarker(ctx context.Context, marker string) error {
	waitCtx, cancel := context.WithTimeout(ctx, markerConfirmTimeout)
	defer cancel()
	stop := context.AfterFunc(m.lifetime, cancel)
	defer stop()

	exited := m.process.Exited()
	ticker := time.NewTicker(markerPollInterval)
	defer ticker.Stop()

	unanswered := 0
	for {
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
			// telemt reads the config file for this list: it cannot parse
			// the render.
			if apiErr.StatusCode >= http.StatusInternalServerError && strings.Contains(apiErr.Message, "failed to load config") {
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
