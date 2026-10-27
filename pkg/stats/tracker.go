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

	// Kernel counters only go down when the peer was re-created. The backend marks the
	// resets it causes itself; this catches any other one (it cannot see a new counter
	// that already passed the old value).
	if sample.Rx < entry.CurrentRx || sample.Tx < entry.CurrentTx {
		rebaseForCounterReset(entry)
	}

	// Skip update if values haven't changed
	if entry.CurrentRx == sample.Rx && entry.CurrentTx == sample.Tx {
		entry.EndpointIP = sample.EndpointIP
		return
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

// rebaseForCounterReset keeps the unreported delta across a kernel counter reset: the
// counter restarts at zero and the baseline becomes -pending, so the next sample is
// reported in full on top of what was still pending. Calling it again before a new
// sample changes nothing.
func rebaseForCounterReset(entry *Entry) {
	entry.BaseRx = -max(entry.CurrentRx-entry.BaseRx, 0)
	entry.BaseTx = -max(entry.CurrentTx-entry.BaseTx, 0)
	entry.CurrentRx = 0
	entry.CurrentTx = 0
}

// MarkCounterReset records that the kernel re-created these peers, so their counters
// restarted at zero. Pending traffic is kept and the next sample counts in full, even
// when it is already above the old counter. Only mark peers that really were re-created,
// and never apply a sample read before the reset after this call: either would report
// the old counter a second time.
func (st *Tracker) MarkCounterReset(keys []string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	for _, key := range keys {
		if entry, exists := st.stats[key]; exists {
			rebaseForCounterReset(entry)
		}
	}
}

// RemoveStats marks a peer as deleted but keeps counters until a reset reports them.
func (st *Tracker) RemoveStats(publicKey string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	entry, exists := st.stats[publicKey]
	if !exists {
		return
	}

	// The kernel peer is gone with its counters: a re-add of this key starts a new
	// counter at zero, while the pending delta stays reportable.
	rebaseForCounterReset(entry)

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
