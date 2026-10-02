package singbox

import (
	"context"
	"errors"
	"log"
	"slices"
	"time"

	"github.com/pasarguard/node/common"
)

// User changes cannot be applied live (sing-box has no per-user hot API outside
// shadowsocks SSM), so every sync path rewrites inbound.users[] and restarts
// the core — the same semantics xray uses for its full-snapshot SyncUsers path.
// Counter loss on restart matches xray behaviour (panel polls with reset=true
// every 10s; at most one poll interval of traffic is dropped).

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

// applyUsers installs the given snapshot and restarts the core; on failure it
// restores the previous snapshot and restarts back into it.
func (s *SingBox) applyUsers(ctx context.Context, snapshot []*common.User, replace bool) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	previous := s.users
	candidate := s.config.Clone()
	if replace {
		s.users = snapshot
	} else {
		s.users = s.upsertUsers(snapshot)
	}
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

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.checkSingBoxStatus(ctx); err != nil {
		return err
	}
	return nil
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
