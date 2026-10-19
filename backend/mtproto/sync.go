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
	if err := m.lockSync(ctx); err != nil {
		return err
	}
	desired, _ := ActiveUsersFromCommon(users, m.config.InboundTag)

	// Nothing to apply: skip the render and the wait for telemt.
	if m.confirmedLocked() && maps.EqualFunc(m.desired, desired, runtimeUserEqual) {
		m.syncMu.Unlock()
		return nil
	}
	return m.applyFullDetachedLocked(ctx, desired)
}

// UpdateUsers applies users on top of the current ones. Up to
// partialApplyMaxUsers changes go through telemt's user API; more, or an
// unconfirmed telemt state, go through a config render and reload. Users
// that did not change are not sent at all.
func (m *MTProto) UpdateUsers(ctx context.Context, users []*common.User) error {
	if err := m.lockSync(ctx); err != nil {
		return err
	}
	next, full := m.updateUsersLocked(ctx, users)
	if !full {
		m.syncMu.Unlock()
		return nil
	}
	return m.applyFullDetachedLocked(ctx, next)
}

// UpdateUsersAndRestart applies users on top of the current ones through a
// config render and reload.
func (m *MTProto) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	if err := m.lockSync(ctx); err != nil {
		return err
	}
	return m.applyFullDetachedLocked(ctx, m.buildNextDesiredLocked(users))
}

// lockSync takes syncMu for a sync call. A caller waiting behind another
// apply gives up at its own deadline, and every waiter on Shutdown. A closed
// backend or a caller already gone is refused.
func (m *MTProto) lockSync(ctx context.Context) error {
	if err := m.syncMu.LockContext(ctx, m.lifetime.Done()); err != nil {
		return err
	}
	if err := m.syncAllowedLocked(ctx); err != nil {
		m.syncMu.Unlock()
		return err
	}
	return nil
}

// syncAllowedLocked refuses a sync after Shutdown, or one whose caller gave
// up while it queued on syncMu. Requires syncMu.
func (m *MTProto) syncAllowedLocked(ctx context.Context) error {
	if m.closed || m.lifetime.Err() != nil {
		return errClosed
	}
	return ctx.Err()
}

// updateUsersLocked applies users through telemt's user API when it can and
// reports whether next needs a full apply instead. Requires syncMu.
func (m *MTProto) updateUsersLocked(ctx context.Context, users []*common.User) (next map[string]*runtimeUser, full bool) {
	next = m.buildNextDesiredLocked(users)
	changes := m.userChangesLocked(users, next)

	if !m.confirmedLocked() || len(changes) > partialApplyMaxUsers {
		return next, true
	}
	if len(changes) == 0 {
		return next, false
	}
	if err := m.applyUserChangesLocked(ctx, changes); err != nil {
		// Some changes may have reached telemt: its users are unknown until
		// a full apply succeeds.
		m.needsFullApply = true
		log.Printf("mtproto: applying %d user changes through the telemt API failed, rendering all users instead: %v", len(changes), err)
		return next, true
	}
	m.confirmLocked(next)
	return next, false
}

// confirmedLocked reports whether telemt runs and has published exactly
// m.desired, with no user API write whose outcome is unknown. Requires
// syncMu.
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

// applyUserChangesLocked sends each change to telemt's user API, stopping at
// the first failure. Requires syncMu.
func (m *MTProto) applyUserChangesLocked(ctx context.Context, changes []userChange) error {
	for _, change := range changes {
		if err := m.sendUserChangeLocked(ctx, change); err != nil {
			return fmt.Errorf("user %s: %w", change.username, err)
		}
	}
	return nil
}

// applyFullDetachedLocked runs applyFullLocked in the background and waits
// for it or for ctx. It takes over syncMu from the caller and releases it
// once the apply settles, so the render, telemt's verdict and the restore of
// a rejected config all happen even when the caller gives up, which a panel
// deadline (10 to 15 s) does before markerConfirmTimeout. That caller gets
// ctx's error at once, and the outcome is logged instead.
func (m *MTProto) applyFullDetachedLocked(ctx context.Context, desired map[string]*runtimeUser) error {
	// Do not start a render for a caller already gone.
	if err := ctx.Err(); err != nil {
		m.syncMu.Unlock()
		return err
	}

	applyCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stopOnShutdown := context.AfterFunc(m.lifetime, cancel)
	result := make(chan error)
	callerGone := make(chan struct{})
	// Shutdown waits for this goroutine: it is added under syncMu before
	// closed is set.
	m.background.Go(func() {
		defer m.syncMu.Unlock()
		defer cancel()
		defer stopOnShutdown()

		err := m.applyFullLocked(applyCtx, desired)
		select {
		case result <- err:
		case <-callerGone:
			logSettledApply(err)
		}
	})

	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		close(callerGone)
		return fmt.Errorf("the users are still being applied: %w", ctx.Err())
	}
}

// logSettledApply logs how a full apply ended after its caller stopped
// waiting. A rejection is already in telemt's log stream.
func logSettledApply(err error) {
	switch {
	case err == nil:
		log.Println("mtproto: telemt loaded the new users after the caller stopped waiting")
	case errors.Is(err, errClosed), errors.Is(err, errReloadRejected):
	default:
		log.Printf("mtproto: applying the users failed after the caller stopped waiting: %v", err)
	}
}

// applyFullLocked renders desired and makes telemt run it: a hot reload of
// the running telemt, or a start when none runs. m.desired takes desired only
// once telemt published it. Requires syncMu.
func (m *MTProto) applyFullLocked(ctx context.Context, desired map[string]*runtimeUser) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if !m.process.Started() {
		if err := m.writeRenderedConfigLocked(desired); err != nil {
			return err
		}
		if err := m.startLocked(ctx); err != nil {
			return err
		}
		m.confirmLocked(desired)
		return nil
	}

	m.matchAPIWritesLocked(ctx, desired)
	if err := m.writeRenderedConfigLocked(desired); err != nil {
		return err
	}

	err := m.reloadLocked(ctx)
	switch {
	case err == nil:
		m.confirmLocked(desired)
		m.forgetSettledAPIWritesLocked()
		return nil
	case errors.Is(err, errReloadRejected):
		m.process.Notice("mtproto: " + strings.ReplaceAll(err.Error(), "\n", " | ") + "; rendering the previous users again")
		if restoreErr := m.restoreLocked(ctx); restoreErr != nil {
			m.needsFullApply = true
			return fmt.Errorf("%w (restoring the previous telemt config failed: %v)", err, restoreErr)
		}
		return err
	default:
		// The outcome is unknown, and telemt may still load the new config.
		m.needsFullApply = true
		return err
	}
}

// restoreLocked renders m.desired again after telemt did not load a render:
// telemt keeps running the previous users, and it watches the config file,
// so the rejected file must not stay there. The restore is not confirmed. If
// telemt was only slow and loads the rejected render after all, the restore
// render follows it. Requires syncMu.
func (m *MTProto) restoreLocked(ctx context.Context) error {
	m.matchAPIWritesLocked(ctx, m.desired)
	if m.hasUnknownAPIWritesLocked() {
		m.needsFullApply = true
	}
	if err := m.writeRenderedConfigLocked(m.desired); err != nil {
		return err
	}
	if err := m.signalReloadLocked(); err != nil {
		log.Printf("warning: %v", err)
	}
	return nil
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
