package mtproto

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"strings"
	"time"

	"github.com/pasarguard/node/common"
)

// partialApplyMaxUsers is the most user changes a batch sends one by one
// through telemt's user API. telemt loads, validates and rewrites its whole
// config for each such call, so a larger batch renders the config once and
// reloads it instead.
const partialApplyMaxUsers = 32

// markerPollInterval is how often the node checks whether telemt loaded a
// rendered config.
const markerPollInterval = 200 * time.Millisecond

// markerConfirmTimeout bounds the wait for telemt to load a rendered config;
// a config it did not load by then counts as rejected. It is a variable so
// tests can lower it.
var markerConfirmTimeout = 30 * time.Second

// errReloadRejected marks a rendered config telemt did not load. telemt
// keeps running the config it had.
var errReloadRejected = errors.New("telemt did not load the new config")

// userChange is one user to create, patch or delete in telemt.
type userChange struct {
	username string
	user     *runtimeUser // the new state; nil deletes the user
	known    bool         // the user is in m.desired
}

func (m *MTProto) SyncUser(ctx context.Context, user *common.User) error {
	// The batch paths skip a user that fails validation; a single-user sync
	// reports it to the caller instead.
	if _, _, err := activeUserFromCommon(user, m.config.InboundTag); err != nil {
		return err
	}
	return m.UpdateUsers(ctx, []*common.User{user})
}

// SyncUsers replaces all users through one config render and reload.
func (m *MTProto) SyncUsers(ctx context.Context, users []*common.User) error {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	if err := m.syncAllowedLocked(ctx); err != nil {
		return err
	}
	desired, _ := ActiveUsersFromCommon(users, m.config.InboundTag)

	// Nothing to apply: skip the render and the wait for telemt.
	if m.confirmedLocked() && maps.EqualFunc(m.desired, desired, runtimeUserEqual) {
		return nil
	}
	return m.applyFullLocked(ctx, desired)
}

// UpdateUsers applies users on top of the current ones. Up to
// partialApplyMaxUsers changes go through telemt's user API; more, or an
// unconfirmed telemt state, go through a config render and reload. Users
// that did not change are not sent at all.
func (m *MTProto) UpdateUsers(ctx context.Context, users []*common.User) error {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	if err := m.syncAllowedLocked(ctx); err != nil {
		return err
	}
	next := m.buildNextDesiredLocked(users)
	changes := m.userChangesLocked(users, next)

	if !m.confirmedLocked() || len(changes) > partialApplyMaxUsers {
		return m.applyFullLocked(ctx, next)
	}
	if len(changes) == 0 {
		return nil
	}

	if err := m.applyUserChangesLocked(ctx, changes); err != nil {
		// Some changes may have reached telemt: its users are unknown until
		// a full apply succeeds.
		m.needsFullApply = true
		log.Printf("mtproto: applying %d user changes through the telemt API failed, rendering all users instead: %v", len(changes), err)
		return m.applyFullLocked(ctx, next)
	}
	m.confirmLocked(next)
	return nil
}

// UpdateUsersAndRestart applies users on top of the current ones through a
// config render and reload.
func (m *MTProto) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	if err := m.syncAllowedLocked(ctx); err != nil {
		return err
	}
	return m.applyFullLocked(ctx, m.buildNextDesiredLocked(users))
}

// syncAllowedLocked refuses a sync after Shutdown, or one whose caller gave
// up while it queued on syncMu. Requires syncMu.
func (m *MTProto) syncAllowedLocked(ctx context.Context) error {
	if m.closed {
		return errClosed
	}
	return ctx.Err()
}

// confirmedLocked reports whether telemt runs and runs exactly m.desired.
// Requires syncMu.
func (m *MTProto) confirmedLocked() bool {
	return !m.needsFullApply && m.process.Started()
}

// buildNextDesiredLocked applies users on top of m.desired. A user that fails
// validation is logged and treated as not included, like an untagged one.
// Requires syncMu.
func (m *MTProto) buildNextDesiredLocked(users []*common.User) map[string]*runtimeUser {
	nextDesired := cloneRuntimeUserMap(m.desired)
	for _, user := range users {
		if user == nil {
			continue
		}

		username := strings.TrimSpace(user.GetEmail())
		runtimeUser, include, err := activeUserFromCommon(user, m.config.InboundTag)
		if err != nil {
			logSkippedUser(username, err)
		}
		if include {
			nextDesired[runtimeUser.Username] = runtimeUser
			continue
		}
		delete(nextDesired, username)
	}
	return nextDesired
}

// userChangesLocked lists, in batch order, the users of the batch whose
// state in next differs from m.desired. Requires syncMu.
func (m *MTProto) userChangesLocked(users []*common.User, next map[string]*runtimeUser) []userChange {
	var changes []userChange
	seen := make(map[string]struct{}, len(users))
	for _, user := range users {
		if user == nil {
			continue
		}
		username := strings.TrimSpace(user.GetEmail())
		if _, done := seen[username]; done {
			continue
		}
		seen[username] = struct{}{}

		current, known := m.desired[username]
		wanted := next[username]
		if !runtimeUserEqual(current, wanted) {
			changes = append(changes, userChange{username: username, user: wanted, known: known})
		}
	}
	return changes
}

// applyUserChangesLocked sends each change to telemt's user API. m.desired
// picks create or patch; when telemt disagrees, its answer corrects the
// choice: a patch of a missing user creates it, a create of an existing user
// patches it, and deleting a missing user is done. Requires syncMu.
func (m *MTProto) applyUserChangesLocked(ctx context.Context, changes []userChange) error {
	for _, change := range changes {
		var err error
		switch {
		case change.user == nil:
			err = m.deleteUser(ctx, change.username)
		case change.known:
			err = m.patchOrCreateUser(ctx, change.user)
		default:
			err = m.createOrPatchUser(ctx, change.user)
		}
		if err != nil {
			return fmt.Errorf("user %s: %w", change.username, err)
		}
	}
	return nil
}

func (m *MTProto) patchOrCreateUser(ctx context.Context, user *runtimeUser) error {
	err := m.apiClient.PatchUser(ctx, user.Username, user)
	var apiErr *apiStatusError
	if errors.As(err, &apiErr) && apiErr.NotFound() {
		return m.apiClient.CreateUser(ctx, user)
	}
	return err
}

func (m *MTProto) createOrPatchUser(ctx context.Context, user *runtimeUser) error {
	err := m.apiClient.CreateUser(ctx, user)
	var apiErr *apiStatusError
	if errors.As(err, &apiErr) && apiErr.UserExists() {
		return m.apiClient.PatchUser(ctx, user.Username, user)
	}
	return err
}

func (m *MTProto) deleteUser(ctx context.Context, username string) error {
	err := m.apiClient.DeleteUser(ctx, username)
	var apiErr *apiStatusError
	if errors.As(err, &apiErr) && apiErr.NotFound() {
		return nil
	}
	return err
}

// applyFullLocked renders desired and makes telemt run it: a hot reload of
// the running telemt, or a start when none runs. m.desired takes desired only
// once telemt confirmed it. Requires syncMu.
func (m *MTProto) applyFullLocked(ctx context.Context, desired map[string]*runtimeUser) error {
	// A partial apply that failed on an expired ctx falls back here; do not
	// rewrite the config for a caller that is gone.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.writeRenderedConfigLocked(desired); err != nil {
		return err
	}

	if !m.process.Started() {
		if err := m.startLocked(ctx); err != nil {
			return err
		}
		m.confirmLocked(desired)
		return nil
	}

	err := m.reloadLocked(ctx)
	switch {
	case err == nil:
		m.confirmLocked(desired)
		return nil
	case errors.Is(err, errReloadRejected):
		// telemt still runs the users it had. Put them back on disk too:
		// telemt watches the config file and would retry the rejected one.
		if restoreErr := m.writeRenderedConfigLocked(m.desired); restoreErr != nil {
			return fmt.Errorf("%w (restoring the previous telemt config failed: %v)", err, restoreErr)
		}
		if signalErr := m.process.Reload(); signalErr != nil {
			log.Printf("warning: %v", signalErr)
		}
		return err
	default:
		// The outcome is unknown, and telemt may still load the new config.
		m.needsFullApply = true
		return err
	}
}

// reloadLocked makes the running telemt hot-reload the rendered config:
// SIGHUP (telemt's config watcher also sees the file change), then a wait
// until the render's marker user is in telemt's running config. A hot reload
// replaces only the users that changed; an API reload would cut every
// session. Only an API that cannot be reached, or a telemt that cannot be
// signalled, restarts telemt, on the rendered config; a caller that gave up
// or a rejected config never does. Requires syncMu.
func (m *MTProto) reloadLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	// telemt is down now: start it again even if the caller gives up.
	if restartErr := m.startLocked(context.WithoutCancel(ctx)); restartErr != nil {
		return fmt.Errorf("telemt reload failed: %w (restart failed: %v)", err, restartErr)
	}
	return nil
}

// waitForMarker polls GET /v1/users until telemt's running config has the
// marker user, for up to markerConfirmTimeout. It returns ctx's error once
// the caller gives up, errClosed on Shutdown, an errReloadRejected error with
// telemt's last output when the time is up, and the request error when the
// API cannot be reached.
func (m *MTProto) waitForMarker(ctx context.Context, marker string) error {
	// Requests do not end with the caller's ctx, so an aborted request is
	// never mistaken for an unreachable API.
	waitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), markerConfirmTimeout)
	defer cancel()
	stop := context.AfterFunc(m.lifetime, cancel)
	defer stop()

	ticker := time.NewTicker(markerPollInterval)
	defer ticker.Stop()

	for {
		users, err := m.apiClient.ListUsers(waitCtx)
		if err == nil && userInRuntime(users, marker) {
			return nil
		}
		var apiErr *apiStatusError
		if err != nil && !errors.As(err, &apiErr) && waitCtx.Err() == nil {
			return fmt.Errorf("telemt API unreachable: %w", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-waitCtx.Done():
			if m.lifetime.Err() != nil {
				return errClosed
			}
			return m.reloadRejectedError()
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

// confirmLocked records desired as the users telemt runs. Requires syncMu.
func (m *MTProto) confirmLocked(desired map[string]*runtimeUser) {
	m.needsFullApply = false
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	m.desired = cloneRuntimeUserMap(desired)
}

// writeRenderedConfigLocked writes desired plus a new marker user to the
// config file and records that marker. Requires syncMu.
func (m *MTProto) writeRenderedConfigLocked(desired map[string]*runtimeUser) error {
	marker, err := newMarkerUser()
	if err != nil {
		return err
	}
	rendered, err := m.config.Render(desired, marker, m.apiPort, m.metricsPort, m.apiAuthHeader)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(m.configPath, []byte(rendered)); err != nil {
		return err
	}

	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	m.marker = marker
	return nil
}

// runtimeUserEqual reports whether a and b give telemt the same user.
func runtimeUserEqual(a, b *runtimeUser) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
