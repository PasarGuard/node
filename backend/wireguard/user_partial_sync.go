package wireguard

import (
	"fmt"

	"github.com/pasarguard/node/common"
)

// buildExistingPeersSubsetForTouched returns the subset of store peers whose email
// is in touchedEmails, keyed by public key — ready for use in buildSyncDiff.
// Uses O(1) per-email lookups via PeerStore instead of scanning all peers.
func (wg *WireGuard) buildExistingPeersSubsetForTouched(touchedEmails map[string]struct{}) map[string]*PeerInfo {
	result := make(map[string]*PeerInfo, len(touchedEmails))
	for email := range touchedEmails {
		if peer := wg.peerStore.GetByEmail(email); peer != nil {
			result[peer.PublicKey.String()] = peer
		}
	}
	return result
}

func (wg *WireGuard) syncUsersPartialReconcile(users []*common.User) error {
	normalizedUsers := normalizeUsers(users)
	touchedEmails := make(map[string]struct{}, len(normalizedUsers))
	for _, user := range normalizedUsers {
		touchedEmails[user.GetEmail()] = struct{}{}
	}

	existingSubset := wg.buildExistingPeersSubsetForTouched(touchedEmails)

	desiredPeers, err := wg.collectDesiredPeers(normalizedUsers)
	if err != nil {
		return err
	}

	currentOwners := wg.peerStore.GetEmailMap()
	for key, desired := range desiredPeers {
		currentOwner, exists := currentOwners[key]
		if !exists || currentOwner == desired.Email {
			continue
		}
		if _, touched := touchedEmails[currentOwner]; !touched {
			return fmt.Errorf("wireguard public key %s is already assigned to user %s", key, currentOwner)
		}
	}

	diff, err := wg.buildSyncDiff(existingSubset, desiredPeers)
	if err != nil {
		return err
	}

	if len(diff.PeerConfigs) > 0 {
		wg.mu.RLock()
		if err := wg.ensureRunningWithManagerLocked(); err != nil {
			wg.mu.RUnlock()
			return err
		}
		manager := wg.manager
		wg.mu.RUnlock()

		if err := manager.ApplyPeers(diff.PeerConfigs); err != nil {
			return fmt.Errorf("failed to apply peer changes: %w", err)
		}
	}

	removedKeys := wg.peerStore.ApplyChanges(diff.RemoveKeys, diff.UpsertPeers)
	for _, key := range removedKeys {
		wg.statsTracker.RemoveStats(key)
	}

	return nil
}
