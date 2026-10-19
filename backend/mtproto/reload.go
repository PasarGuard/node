package mtproto

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
// does not send SIGHUP where it cannot see telemt's signal handlers (see
// telemtHandlesSIGHUPLocked). It is a variable so tests can lower it.
var telemtSignalGrace = 5 * time.Second

// readSIGHUPCaught is sighupCaught; tests replace it to make the node fall
// back to telemtSignalGrace.
var readSIGHUPCaught = sighupCaught

// markerConfirmTimeout bounds the wait for telemt to load a rendered config;
// a config it did not load by then counts as rejected. It is a variable so
// tests can lower it.
var markerConfirmTimeout = 30 * time.Second

// errReloadRejected marks a rendered config telemt did not load. telemt
// keeps running the config it had.
var errReloadRejected = errors.New("telemt did not load the new config")

// markerUsernamePrefix starts every marker username. Panel usernames are
// numeric user ids, so no real user has it.
const markerUsernamePrefix = "pgm_"

// newMarkerUser returns a marker user with a fresh random name and secret.
// Every render carries one, disabled: once telemt's running config has it,
// telemt has published that render (its user admission follows from the
// published config shortly after). It also keeps telemt's user list
// non-empty.
func newMarkerUser() (*runtimeUser, error) {
	secret := make([]byte, 16)
	usernameSuffix := make([]byte, 8)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate the mtproto marker secret: %w", err)
	}
	if _, err := rand.Read(usernameSuffix); err != nil {
		return nil, fmt.Errorf("failed to generate the mtproto marker username: %w", err)
	}

	return &runtimeUser{
		Username: markerUsernamePrefix + hex.EncodeToString(usernameSuffix),
		Secret:   hex.EncodeToString(secret),
	}, nil
}

// reloadLocked makes the running telemt hot-reload the rendered config and
// waits until the render's marker user is in telemt's running config.
// telemt's config watcher sees the file change, and SIGHUP makes sure once
// telemt handles it (see waitForMarkerLocked). A hot reload replaces
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
	err := m.waitForMarkerLocked(ctx, m.marker.Username)
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

// signalReloadLocked sends telemt SIGHUP if it handles the signal yet (see
// telemtHandlesSIGHUPLocked); before that, telemt's config watcher sees the
// change. Requires syncMu.
func (m *MTProto) signalReloadLocked() error {
	if !m.telemtHandlesSIGHUPLocked() {
		return nil
	}
	return m.process.Reload()
}

// telemtHandlesSIGHUPLocked reports whether the running telemt can take
// SIGHUP. telemt's config watcher installs its SIGHUP handler at the end of
// its own setup, which runs concurrently with the API coming up and can
// finish after the API first answers; a SIGHUP before that ends telemt.
// Once installed, the handler stays for the process lifetime. The watcher
// loads most renders of that window on its own, but misses one written
// while it sets up. On Linux the node reads the handler from telemt's
// SigCgt mask (sighupCaught); elsewhere, or when that read fails, it waits
// telemtSignalGrace after the API first answered. Requires syncMu.
func (m *MTProto) telemtHandlesSIGHUPLocked() bool {
	if caught, err := readSIGHUPCaught(m.process.PID()); err == nil {
		return caught
	}
	return time.Since(m.healthyAt) >= telemtSignalGrace
}

// waitForMarkerLocked polls GET /v1/users until telemt's running config has
// the marker user, for up to markerConfirmTimeout, and sends telemt SIGHUP
// once telemt handles it: at once in steady state, or once the config
// watcher installed the handler if it has not loaded the render by then.
// It returns an errReloadRejected error when telemt cannot read the
// rendered file or the time is up, errClosed on Shutdown, ctx's error when
// ctx ends, and the signal or request error when telemt cannot be
// signalled, the API stays unreachable or telemt exited. Requires syncMu.
func (m *MTProto) waitForMarkerLocked(ctx context.Context, marker string) error {
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
		if !signalled && m.telemtHandlesSIGHUPLocked() {
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
