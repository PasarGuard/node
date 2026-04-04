package wireguard

import (
	"context"
	"fmt"

	"github.com/pasarguard/node/common"
)

// SyncUser synchronizes a single user to the WireGuard interface.
// Each user has a single key/IP pair (/32 for IPv4, /128 for IPv6).
func (wg *WireGuard) SyncUser(_ context.Context, user *common.User) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}

	wg.syncMu.Lock()
	defer wg.syncMu.Unlock()

	return wg.syncUsersPartialReconcile([]*common.User{user})
}

// SyncUsers synchronizes multiple users to the WireGuard interface.
func (wg *WireGuard) SyncUsers(_ context.Context, users []*common.User) error {
	wg.syncMu.Lock()
	defer wg.syncMu.Unlock()

	return wg.syncUsersFull(users)
}

// UpdateUsers performs partial reconciliation for users provided in the request.
func (wg *WireGuard) UpdateUsers(_ context.Context, users []*common.User) error {
	wg.syncMu.Lock()
	defer wg.syncMu.Unlock()

	return wg.syncUsersPartialReconcile(users)
}

// UpdateUsersAndRestart applies targeted user updates, then rebuilds the full
// peer snapshot so interface-wide settings like keepalive are reapplied to all peers.
func (wg *WireGuard) UpdateUsersAndRestart(_ context.Context, users []*common.User) error {
	wg.syncMu.Lock()
	defer wg.syncMu.Unlock()

	if err := wg.syncUsersPartialReconcile(users); err != nil {
		return err
	}

	return wg.restartLocked()
}
