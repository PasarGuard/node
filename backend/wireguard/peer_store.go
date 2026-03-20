package wireguard

import (
	"sync"
)

// PeerStore manages the runtime state of WireGuard peers.
// It enforces a 1:1 mapping between User (Email) and WireGuard Public Key.
type PeerStore struct {
	mu         sync.RWMutex
	peers      map[string]*PeerInfo // publicKey -> PeerInfo
	emailToKey map[string]string    // email -> publicKey (1:1 mapping)
}

// NewPeerStore creates a new empty PeerStore
func NewPeerStore() *PeerStore {
	return &PeerStore{
		peers:      make(map[string]*PeerInfo),
		emailToKey: make(map[string]string),
	}
}

// Init bulk initializes the peer store.
// Should ONLY be used during startup when the store is known to be empty.
func (ps *PeerStore) Init(peers []*PeerInfo) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	for _, peer := range peers {
		if peer == nil {
			continue
		}
		peerCopy := clonePeerInfo(peer)
		keyStr := peerCopy.PublicKey.String()
		ps.peers[keyStr] = peerCopy
		ps.emailToKey[peerCopy.Email] = keyStr
	}
}

// ApplyChanges commits removals and upserts in one lock scope.
// It returns the keys actually removed from the store.
func (ps *PeerStore) ApplyChanges(removeKeys []string, upsertPeers []*PeerInfo) []string {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	removed := make([]string, 0, len(removeKeys))

	for _, key := range removeKeys {
		if peer, exists := ps.peers[key]; exists {
			delete(ps.emailToKey, peer.Email)
			delete(ps.peers, key)
			removed = append(removed, key)
		}
	}

	for _, peer := range upsertPeers {
		if peer == nil {
			continue
		}

		peerCopy := clonePeerInfo(peer)

		if oldKey, exists := ps.emailToKey[peerCopy.Email]; exists && oldKey != peerCopy.PublicKey.String() {
			delete(ps.peers, oldKey)
		}

		if existingPeer, exists := ps.peers[peerCopy.PublicKey.String()]; exists && existingPeer.Email != peerCopy.Email {
			delete(ps.emailToKey, existingPeer.Email)
		}

		ps.peers[peerCopy.PublicKey.String()] = peerCopy
		ps.emailToKey[peerCopy.Email] = peerCopy.PublicKey.String()
	}

	return removed
}

// ReplaceAll completely replaces the peer store contents with the given peers.
// It returns a list of public keys that were removed in the process.
func (ps *PeerStore) ReplaceAll(peers []*PeerInfo) []string {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	newPeers := make(map[string]*PeerInfo, len(peers))
	newEmailToKey := make(map[string]string, len(peers))

	for _, peer := range peers {
		if peer == nil {
			continue
		}
		peerCopy := clonePeerInfo(peer)
		keyStr := peerCopy.PublicKey.String()
		newPeers[keyStr] = peerCopy
		newEmailToKey[peerCopy.Email] = keyStr
	}

	var removed []string
	for oldKey := range ps.peers {
		if _, exists := newPeers[oldKey]; !exists {
			removed = append(removed, oldKey)
		}
	}

	ps.peers = newPeers
	ps.emailToKey = newEmailToKey

	return removed
}

// GetByEmail returns the peer for a given email if it exists.
func (ps *PeerStore) GetByEmail(email string) *PeerInfo {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if key, exists := ps.emailToKey[email]; exists {
		return clonePeerInfo(ps.peers[key])
	}
	return nil
}

// GetByKey returns a single peer by public key.
func (ps *PeerStore) GetByKey(publicKey string) *PeerInfo {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	return clonePeerInfo(ps.peers[publicKey])
}

// GetAll returns all configured peers.
func (ps *PeerStore) GetAll() []*PeerInfo {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	result := make([]*PeerInfo, 0, len(ps.peers))
	for _, peer := range ps.peers {
		result = append(result, clonePeerInfo(peer))
	}
	return result
}

// GetEmailMap returns a completely decoupled, point-in-time map of publicKey -> email.
// Replaces the over-engineered emailByKeySnapshotCache.
func (ps *PeerStore) GetEmailMap() map[string]string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	snapshot := make(map[string]string, len(ps.peers))
	for key, peer := range ps.peers {
		snapshot[key] = peer.Email
	}
	return snapshot
}
