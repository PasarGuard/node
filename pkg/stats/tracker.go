package stats

import (
	"context"
	"sync"
	"time"

	"github.com/pasarguard/node/common"
)

// Entry tracks stats for one user (map key = public key)
type Entry struct {
	Email          string
	CurrentRx      int64
	CurrentTx      int64
	BaseRx         int64
	BaseTx         int64
	LastDeltaRx    int64
	LastDeltaTx    int64
	LastActiveTime time.Time
	EndpointIP     string
	IsDeleted      bool
}

// Sample is a single stats measurement for one WireGuard peer key.
type Sample struct {
	PublicKey  string
	Email      string
	Rx         int64
	Tx         int64
	EndpointIP string
}

// Tracker manages stats
type Tracker struct {
	stats map[string]*Entry

	mu sync.RWMutex
}

// New creates a new stats tracker
func New() *Tracker {
	return &Tracker{
		stats: make(map[string]*Entry),
	}
}

// UpdateStatsBatch applies many peer stats updates under a single lock.
func (st *Tracker) UpdateStatsBatch(samples []Sample) {
	if len(samples) == 0 {
		return
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	for _, sample := range samples {
		st.applySampleLocked(sample, now)
	}
}

func (st *Tracker) applySampleLocked(sample Sample, activeAt time.Time) {
	entry, exists := st.stats[sample.PublicKey]
	if !exists {
		entry = &Entry{
			Email: sample.Email,
		}
		st.stats[sample.PublicKey] = entry
	}
	entry.Email = sample.Email
	entry.IsDeleted = false

	// Restore pending delta baseline when a deleted entry is re-added.
	readded := false
	if entry.LastDeltaRx != 0 || entry.LastDeltaTx != 0 {
		entry.BaseRx = sample.Rx - entry.LastDeltaRx
		entry.BaseTx = sample.Tx - entry.LastDeltaTx
		entry.LastDeltaRx = 0
		entry.LastDeltaTx = 0
		readded = true
	}

	// Skip update if values haven't changed
	if entry.CurrentRx == sample.Rx && entry.CurrentTx == sample.Tx {
		entry.EndpointIP = sample.EndpointIP
		return
	}

	// Detect kernel counter rollback/reset and preserve pending deltas
	if !readded && (sample.Rx < entry.CurrentRx || sample.Tx < entry.CurrentTx) {
		pendingRx := entry.CurrentRx - entry.BaseRx
		pendingTx := entry.CurrentTx - entry.BaseTx
		if pendingRx < 0 {
			pendingRx = 0
		}
		if pendingTx < 0 {
			pendingTx = 0
		}
		entry.BaseRx = sample.Rx - pendingRx
		entry.BaseTx = sample.Tx - pendingTx
	}

	// Any traffic growth implies peer is active.
	if sample.Rx > entry.CurrentRx || sample.Tx > entry.CurrentTx {
		entry.LastActiveTime = activeAt
	}

	entry.CurrentRx = sample.Rx
	entry.CurrentTx = sample.Tx

	// Update endpoint from periodic check.
	entry.EndpointIP = sample.EndpointIP
}

// GetStats returns stats for specific public keys (direct map lookup)
func (st *Tracker) GetStats(_ context.Context, keys []string, reset bool) *common.StatResponse {
	if reset {
		st.mu.Lock()
		defer st.mu.Unlock()
	} else {
		st.mu.RLock()
		defer st.mu.RUnlock()
	}

	response := &common.StatResponse{
		Stats: make([]*common.Stat, 0),
	}

	for _, key := range keys {
		entry, exists := st.stats[key]
		if !exists {
			continue
		}

		rx := entry.CurrentRx - entry.BaseRx
		tx := entry.CurrentTx - entry.BaseTx

		// Skip zero-delta entries
		stats := buildDeltaStats(entry.Email, key, rx, tx)
		response.Stats = append(response.Stats, stats...)

		if reset {
			entry.BaseRx = entry.CurrentRx
			entry.BaseTx = entry.CurrentTx
			if entry.IsDeleted {
				delete(st.stats, key)
			}
		}
	}

	return response
}

// GetUsersStats returns stats for all public keys (all users)
func (st *Tracker) GetUsersStats(_ context.Context, reset bool) *common.StatResponse {
	if reset {
		st.mu.Lock()
		defer st.mu.Unlock()
	} else {
		st.mu.RLock()
		defer st.mu.RUnlock()
	}

	response := &common.StatResponse{
		Stats: make([]*common.Stat, 0, len(st.stats)*2),
	}

	for key, entry := range st.stats {
		rx := entry.CurrentRx - entry.BaseRx
		tx := entry.CurrentTx - entry.BaseTx

		// Skip zero-delta entries
		stats := buildDeltaStats(entry.Email, key, rx, tx)
		response.Stats = append(response.Stats, stats...)

		if reset {
			entry.BaseRx = entry.CurrentRx
			entry.BaseTx = entry.CurrentTx
			if entry.IsDeleted {
				delete(st.stats, key)
			}
		}
	}

	return response
}

// GetStatsEntries returns stats entries for specific public keys
func (st *Tracker) GetStatsEntries(keys []string) map[string]*Entry {
	st.mu.RLock()
	defer st.mu.RUnlock()

	result := make(map[string]*Entry)
	for _, key := range keys {
		if entry, exists := st.stats[key]; exists {
			// Return copy to prevent external modification
			result[key] = &Entry{
				Email:          entry.Email,
				CurrentRx:      entry.CurrentRx,
				CurrentTx:      entry.CurrentTx,
				BaseRx:         entry.BaseRx,
				BaseTx:         entry.BaseTx,
				LastDeltaRx:    entry.LastDeltaRx,
				LastDeltaTx:    entry.LastDeltaTx,
				LastActiveTime: entry.LastActiveTime,
				EndpointIP:     entry.EndpointIP,
				IsDeleted:      entry.IsDeleted,
			}
		}
	}

	return result
}

// AnyActiveSince reports whether any key has activity after the provided cutoff.
func (st *Tracker) AnyActiveSince(keys []string, cutoff time.Time) bool {
	st.mu.RLock()
	defer st.mu.RUnlock()

	for _, key := range keys {
		entry, exists := st.stats[key]
		if !exists {
			continue
		}
		if entry.LastActiveTime.After(cutoff) {
			return true
		}
	}

	return false
}

// EndpointActivity returns endpoint IP -> last seen unix timestamp for provided keys.
// If multiple keys share endpoint IP, the newest timestamp wins.
func (st *Tracker) EndpointActivity(keys []string) map[string]int64 {
	st.mu.RLock()
	defer st.mu.RUnlock()

	var result map[string]int64
	for _, key := range keys {
		entry, exists := st.stats[key]
		if !exists || entry.EndpointIP == "" || entry.LastActiveTime.IsZero() {
			continue
		}

		ts := entry.LastActiveTime.Unix()
		if result == nil {
			result = make(map[string]int64)
		}

		if prev, ok := result[entry.EndpointIP]; !ok || ts > prev {
			result[entry.EndpointIP] = ts
		}
	}

	return result
}

// RemoveStats marks a peer as deleted but keeps counters until a reset reports them.
func (st *Tracker) RemoveStats(publicKey string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	entry, exists := st.stats[publicKey]
	if !exists {
		return
	}

	// Persist pending deltas so re-add before stats pull won't lose data.
	entry.LastDeltaRx = entry.CurrentRx - entry.BaseRx
	entry.LastDeltaTx = entry.CurrentTx - entry.BaseTx

	// Mark deleted and clear active time so online checks return offline immediately.
	entry.IsDeleted = true
	entry.LastActiveTime = time.Time{}
}

// ClearAllStats clears all stats
func (st *Tracker) ClearAllStats() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.stats = make(map[string]*Entry)
}

// CleanupDeletedEntries removes deleted peers once their remaining delta is fully accounted.
func (st *Tracker) CleanupDeletedEntries() {
	st.mu.Lock()
	defer st.mu.Unlock()

	for key, entry := range st.stats {
		if entry.IsDeleted && entry.CurrentRx == entry.BaseRx && entry.CurrentTx == entry.BaseTx {
			delete(st.stats, key)
		}
	}
}
