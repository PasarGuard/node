package mtproto

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"strings"

	"github.com/pasarguard/node/common"
)

// partialApplyMaxUsers is the most user changes a batch sends one by one
// through telemt's user API. telemt loads, validates and rewrites its whole
// config for each such call, so a larger batch renders the config once and
// reloads it instead.
const partialApplyMaxUsers = 32

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

	// A reload cuts every telemt session; skip one that changes nothing.
	if m.confirmedLocked() && maps.EqualFunc(m.desired, desired, runtimeUserEqual) {
		return nil
	}
	return m.applyFullLocked(ctx, desired)
}

// UpdateUsers applies users on top of the current ones. Up to
// partialApplyMaxUsers changes go through telemt's user API; more, a change
// to or from zero users, or an unconfirmed telemt state go through a config
// render and reload. Users that did not change are not sent at all.
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
	// telemt refuses to delete its last user, and zero users means the
	// sentinel, which only a render adds or drops.
	if len(m.desired) == 0 || len(next) == 0 {
		return m.applyFullLocked(ctx, next)
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

// applyFullLocked renders desired and makes telemt run it: a reload of the
// running telemt, or a start when none runs. m.desired takes desired only
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
	var rejected *reloadRejectedError
	switch {
	case err == nil:
		m.confirmLocked(desired)
		return nil
	case errors.As(err, &rejected):
		// telemt still runs the users it had. Put them back on disk too:
		// telemt watches the config file and would load the rejected one.
		if restoreErr := m.writeRenderedConfigLocked(m.desired); restoreErr != nil {
			return fmt.Errorf("%w (restoring the previous telemt config failed: %v)", err, restoreErr)
		}
		return err
	default:
		// The outcome is unknown, and telemt may still load the new config.
		m.needsFullApply = true
		return err
	}
}

// reloadLocked makes the running telemt load the rendered config through its
// reload API and waits for the outcome. Only a request that cannot reach
// telemt restarts it, on the rendered config; a caller that gave up or a
// rejected config never does. Requires syncMu.
func (m *MTProto) reloadLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	waitCtx, cancel := m.reloadContext(ctx)
	defer cancel()

	err := m.apiClient.Reload(waitCtx)
	switch {
	case err == nil:
		return nil
	case m.lifetime.Err() != nil:
		return errClosed
	case waitCtx.Err() != nil:
		return fmt.Errorf("telemt reload not confirmed: %w", err)
	case !errors.Is(err, errAPIUnreachable):
		return err
	}

	log.Printf("telemt API unreachable for a reload, restarting telemt: %v", err)
	m.process.Stop()
	// telemt is down now: start it again even if the caller gives up.
	if restartErr := m.startLocked(context.WithoutCancel(ctx)); restartErr != nil {
		return fmt.Errorf("telemt reload failed: %w (restart failed: %v)", err, restartErr)
	}
	return nil
}

// reloadContext bounds the wait for a reload by ctx, by Shutdown, and by
// telemtStartupTimeout when ctx has no deadline: syncMu is held throughout.
func (m *MTProto) reloadContext(ctx context.Context) (context.Context, context.CancelFunc) {
	var waitCtx context.Context
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		waitCtx, cancel = context.WithCancel(ctx)
	} else {
		waitCtx, cancel = context.WithTimeout(ctx, telemtStartupTimeout)
	}
	stop := context.AfterFunc(m.lifetime, cancel)
	return waitCtx, func() {
		stop()
		cancel()
	}
}

// confirmLocked records desired as the users telemt runs. Requires syncMu.
func (m *MTProto) confirmLocked(desired map[string]*runtimeUser) {
	m.needsFullApply = false
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	m.desired = cloneRuntimeUserMap(desired)
}

func (m *MTProto) writeRenderedConfigLocked(desired map[string]*runtimeUser) error {
	var sentinel *runtimeUser
	if len(desired) == 0 {
		sentinel = m.sentinel
	}

	rendered, err := m.config.Render(desired, sentinel, m.apiPort, m.metricsPort, m.apiAuthHeader)
	if err != nil {
		return err
	}

	return writeFileAtomic(m.configPath, []byte(rendered))
}

// runtimeUserEqual reports whether a and b give telemt the same user.
func runtimeUserEqual(a, b *runtimeUser) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
