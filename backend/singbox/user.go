package singbox

import (
	"context"
	"errors"
	"log"
	"slices"
	"time"

	"github.com/pasarguard/node/common"
)

// User changes cannot be applied live: sing-box exposes no generic hot user
// API (the SSM API's UpdateUsers is implemented only by the shadowsocks
// MultiInbound — adapter/ssm.go + protocol/shadowsocks/inbound_multi.go), so
// materializing a change rewrites inbound.users[] and restarts the core.
//
// To avoid restart storms, changes coalesce inside a debounce window
// (SINGBOX_SYNC_DEBOUNCE_SECONDS, default 30s; 0 = apply immediately):
// the desired state updates instantly, one restart lands per window, and
// pending counters are drained into pendingStats before every planned
// restart so no usage is lost between panel polls.

func (s *SingBox) upsertUsers(users []*common.User) []*common.User {
	next := make([]*common.User, 0, len(s.users)+len(users))
	next = append(next, s.users...)
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

// applyUsers installs the given snapshot as the desired state. With a debounce
// window the restart is scheduled/coalesced; with window 0 it applies
// synchronously (returns the restart error to the RPC caller).
func (s *SingBox) applyUsers(ctx context.Context, snapshot []*common.User, replace bool) error {
	s.syncMu.Lock()

	if replace {
		s.users = snapshot
	} else {
		s.users = s.upsertUsers(snapshot)
	}
	desiredCount := len(s.users)

	window := time.Duration(0)
	if s.cfg != nil {
		window = s.cfg.SingBoxSyncDebounce
	}
	if window <= 0 {
		err := s.flushLocked(ctx)
		s.syncMu.Unlock()
		return err
	}

	if s.shuttingDown {
		s.syncMu.Unlock()
		return nil
	}

	if s.debounceTimer != nil {
		log.Printf("sing-box: user change coalesced into pending restart (%d users in desired state, restart in flight window)", desiredCount)
		s.syncMu.Unlock()
		return nil
	}

	log.Printf("sing-box: coalescing user changes — restarting in %s (%d users in desired state)", window, desiredCount)
	s.debounceTimer = time.AfterFunc(window, s.debouncedFlush)
	s.syncMu.Unlock()
	return nil
}

// debouncedFlush runs the coalesced restart. Rate limited: if another flush
// landed within the debounce window, the restart is pushed back (backoff on
// repeated failures) so a hot change stream cannot storm the core.
func (s *SingBox) debouncedFlush() {
	s.syncMu.Lock()
	if s.shuttingDown {
		s.debounceTimer = nil
		s.syncMu.Unlock()
		return
	}

	window := time.Duration(0)
	if s.cfg != nil {
		window = s.cfg.SingBoxSyncDebounce
	}
	if window > 0 {
		wait := window << min(s.flushFailures, 3)
		if !s.lastFlushAt.IsZero() && time.Since(s.lastFlushAt) < wait {
			delay := wait - time.Since(s.lastFlushAt)
			log.Printf("sing-box: restart rate-limited, deferring coalesced restart by %s", delay)
			s.debounceTimer = time.AfterFunc(delay, s.debouncedFlush)
			s.syncMu.Unlock()
			return
		}
	}

	err := s.flushLocked(context.Background())
	if err != nil {
		s.flushFailures++
		log.Printf("sing-box: coalesced restart failed (%d consecutive): %v", s.flushFailures, err)
	} else {
		s.flushFailures = 0
	}
	s.debounceTimer = nil
	s.lastFlushAt = time.Now()
	s.syncMu.Unlock()
}

// flushLocked drains live counters into pendingStats, applies the desired
// users to the config, and restarts the core. Caller holds syncMu.
func (s *SingBox) flushLocked(ctx context.Context) error {
	previous := s.users

	s.flushCountersLocked()

	candidate := s.config.Clone()
	candidate.syncUsers(s.users)

	if err := s.restartCoreWithConfig(candidate); err != nil {
		s.users = previous
		rollback := s.config.Clone()
		rollback.syncUsers(previous)
		if rbErr := s.restartCoreWithConfig(rollback); rbErr != nil {
			log.Printf("failed to restore previous sing-box config: %v", rbErr)
		}
		return err
	}
	s.setConfig(candidate)
	s.restartCount++

	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.checkSingBoxStatus(checkCtx); err != nil {
		return err
	}
	log.Printf("sing-box: applied user change (restart #%d, %d users)", s.restartCount, len(s.users))
	return nil
}

// flushCountersLocked reads every per-user counter with reset=true and parks
// the deltas in pendingStats so the next panel poll (which also uses
// reset=true) still receives traffic that flowed before a planned restart.
// Best-effort: the core may already be mid-restart.
func (s *SingBox) flushCountersLocked() {
	if s.handler == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := s.handler.queryStats(ctx, "user>>>", true)
	if err != nil {
		log.Printf("sing-box: pre-restart stats flush skipped: %v", err)
		return
	}
	for _, st := range raw {
		if st.GetValue() == 0 {
			continue
		}
		name, link, statType, ok := parseStatName(st.GetName())
		if !ok {
			continue
		}
		key := name + "|" + statType + "|" + link
		s.pendingStats[key] += st.GetValue()
	}
}

func (s *SingBox) SyncUser(ctx context.Context, user *common.User) error {
	if user.GetEmail() == "" {
		return errors.New("email is required")
	}
	return s.applyUsers(ctx, []*common.User{user}, false)
}

func (s *SingBox) SyncUsers(ctx context.Context, users []*common.User) error {
	return s.applyUsers(ctx, users, true)
}

func (s *SingBox) UpdateUsers(ctx context.Context, users []*common.User) error {
	return s.applyUsers(ctx, users, false)
}

func (s *SingBox) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	return s.applyUsers(ctx, users, false)
}
