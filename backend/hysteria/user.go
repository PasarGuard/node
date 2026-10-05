package hysteria

import (
	"context"
	"errors"
	"log"
	"slices"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// hysteriaExecutablePathEnv is the env var naming the hysteria binary. It is
// read through config.GetEnv rather than from a config.Config field because
// node/config/config.go belongs to core-runtime and batch 1.2 may not edit it;
// a fourth executable field is requested from core-runtime in the agent report.
const hysteriaExecutablePathEnv = "HYSTERIA_EXECUTABLE_PATH"

const defaultHysteriaExecutablePath = "/usr/local/bin/hysteria"

// statsFlushTimeout bounds the pre-restart counter drain. The listener is
// loopback, so a slow answer means the core is already gone; the flush is
// best-effort and must not hold the restart open.
const statsFlushTimeout = 5 * time.Second

// hysteriaExecutablePath resolves the binary for this core.
func hysteriaExecutablePath(cfg *config.Config) string {
	if cfg != nil {
		if custom := config.GetEnv(hysteriaExecutablePathEnv, ""); custom != "" {
			return custom
		}
	}
	return defaultHysteriaExecutablePath
}

// User changes cannot be applied live: auth.userpass is a config block and
// stock hysteria exposes no runtime user API, so materializing a change
// rewrites it and restarts the core. Counters are drained into pendingStats
// first, so the restart window does not lose usage (same rule and same reason
// as sing-box, backend/singbox/user.go:13-21 and :118-135).

func (h *Hysteria) upsertUsers(users []*common.User) []*common.User {
	next := make([]*common.User, 0, len(h.users)+len(users))
	next = append(next, h.users...)
	for _, incoming := range users {
		idx := slices.IndexFunc(next, func(u *common.User) bool {
			return u.GetEmail() == incoming.GetEmail()
		})
		if idx >= 0 {
			next[idx] = incoming
		} else {
			next = append(next, incoming)
		}
	}
	return next
}

// applyUsers installs the given snapshot as the desired state, then makes the
// running core match it.
//
// No debounce window, unlike sing-box: a hysteria restart is one process spawn
// with a small config, and the panel's fan-out already turns a user edit into a
// single call. Add a window if a bulk sync ever restarts this core more than
// once a second.
func (h *Hysteria) applyUsers(ctx context.Context, snapshot []*common.User, replace bool) error {
	h.syncMu.Lock()
	defer h.syncMu.Unlock()

	previous := h.users
	if replace {
		h.users = snapshot
	} else {
		h.users = h.upsertUsers(snapshot)
	}

	if err := h.flushLocked(ctx); err != nil {
		// Roll the desired state back so the next call is not applied on top of
		// a set the core never accepted, and re-run the old one so the core and
		// the panel agree again. The panel is not told about this: it will
		// simply retry with the same input.
		h.users = previous
		rollback := h.getConfig().Clone()
		if rbErr := rollback.syncUsers(previous); rbErr != nil {
			// The rollback carries usernames the core already accepted, so this
			// is unreachable in practice. Log rather than restart onto a config
			// we know is invalid.
			log.Printf("hysteria: rollback config is itself invalid: %v", rbErr)
			return err
		}
		if rbErr := h.restartCoreWithConfig(rollback); rbErr != nil {
			log.Printf("hysteria: failed to restore previous config after a rejected user change: %v", rbErr)
		}
		return err
	}
	return nil
}

// flushLocked drains live counters into pendingStats, applies the desired users
// and restarts the core. Caller holds syncMu.
//
// Order matters and is the reverse of what reads naturally:
//
//  1. drain the counters, so the bytes a removed user just spent are billed;
//  2. kick the removed ids while their connections still exist — the core
//     refuses the next LogTraffic from a kicked id and closes its QUIC
//     connection (core/server/server.go:380-387, :393-400). This is what makes
//     "removing a user cuts its live session" an explicit step rather than a
//     side effect. Kicking after the restart would be a no-op: an id the config
//     no longer authenticates never reaches LogTraffic again;
//  3. restart, which is unavoidable (auth.userpass is a config block) and which
//     also drops the connections of everyone else.
//
// The cost of 3 is that a user change interrupts every other user on this core.
// Inherent to hysteria, not to this adapter: there is no live user API to
// rebuild. Say so rather than pretending a cheaper path exists.
func (h *Hysteria) flushLocked(ctx context.Context) error {
	removed := h.removedSince(h.authenticatedNames())
	h.flushCountersLocked()

	if len(removed) > 0 {
		kickCtx, cancel := context.WithTimeout(ctx, statsFlushTimeout)
		defer cancel()
		if err := h.kickIDs(kickCtx, removed); err != nil {
			// Not fatal: step 3 drops the same connections. Logged because a
			// silent failure here would look like "kick does not work".
			log.Printf("hysteria: kick of removed users failed (the restart drops them anyway): %v", err)
		}
	}

	candidate := h.getConfig().Clone()
	if err := candidate.syncUsers(h.users); err != nil {
		return err
	}

	if err := h.restartCoreWithConfig(candidate); err != nil {
		return err
	}
	h.setConfig(candidate)

	checkCtx, cancel := context.WithTimeout(ctx, statsStartupTimeout)
	defer cancel()
	if err := h.checkStatus(checkCtx); err != nil {
		return err
	}
	h.core.SwitchToRuntimeLogPhase()

	log.Printf("hysteria: applied user change (%d users)", len(h.users))
	return nil
}

// authenticatedNames is the identity set the current config authenticates.
func (h *Hysteria) authenticatedNames() map[string]bool {
	out := map[string]bool{}
	for _, name := range h.getConfig().userNames() {
		out[name] = true
	}
	return out
}

// removedSince returns the names that were authenticated before and are not any
// more. Caller holds syncMu, so h.users is already the desired set.
func (h *Hysteria) removedSince(before map[string]bool) []string {
	wanted := map[string]bool{}
	for _, user := range h.users {
		if email := user.GetEmail(); email != "" {
			wanted[email] = true
		}
	}
	var removed []string
	for name := range before {
		if !wanted[name] {
			removed = append(removed, name)
		}
	}
	slices.Sort(removed)
	return removed
}

func (h *Hysteria) kickIDs(ctx context.Context, ids []string) error {
	h.mu.RLock()
	handler := h.handler
	h.mu.RUnlock()
	if handler == nil {
		return errors.New("hysteria stats client not ready")
	}
	return handler.kick(ctx, ids)
}

// flushCountersLocked reads every per-user counter with clear=true and parks
// the deltas in pendingStats so the next panel poll still receives traffic that
// flowed before this restart. Best-effort: the core may already be mid-restart.
func (h *Hysteria) flushCountersLocked() {
	h.mu.RLock()
	handler := h.handler
	h.mu.RUnlock()
	if handler == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), statsFlushTimeout)
	defer cancel()
	entries, err := handler.traffic(ctx, true)
	if err != nil {
		log.Printf("hysteria: pre-restart stats flush skipped: %v", err)
		return
	}
	for id, entry := range entries {
		if entry.Tx == 0 && entry.Rx == 0 {
			continue
		}
		h.pendingStats[id+"|"+uplinkType] += int64(entry.Tx)
		h.pendingStats[id+"|"+downlinkType] += int64(entry.Rx)
	}
}

func (h *Hysteria) SyncUser(ctx context.Context, user *common.User) error {
	if user.GetEmail() == "" {
		return errors.New("email is required")
	}
	return h.applyUsers(ctx, []*common.User{user}, false)
}

func (h *Hysteria) SyncUsers(ctx context.Context, users []*common.User) error {
	return h.applyUsers(ctx, users, true)
}

func (h *Hysteria) UpdateUsers(ctx context.Context, users []*common.User) error {
	return h.applyUsers(ctx, users, false)
}

// UpdateUsersAndRestart is the same work: there is no live path to take, so
// every user change is already a restart.
func (h *Hysteria) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	return h.applyUsers(ctx, users, false)
}
