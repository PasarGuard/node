package mtproto

import (
	"sync"

	"github.com/pasarguard/node/common"
)

type trafficTracker struct {
	mu      sync.RWMutex
	entries map[string]*trafficEntry
}

type trafficEntry struct {
	CurrentUplink   int64
	CurrentDownlink int64
	BaseUplink      int64
	BaseDownlink    int64
	LastDeltaUplink int64
	LastDeltaDown   int64
	Deleted         bool
}

func newTrafficTracker() *trafficTracker {
	return &trafficTracker{
		entries: make(map[string]*trafficEntry),
	}
}

func (t *trafficTracker) Sync(snapshot map[string]userMetrics, activeUsers map[string]struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for username := range activeUsers {
		counters := snapshot[username]
		t.applySampleLocked(username, counters)
	}

	for username, entry := range t.entries {
		if _, ok := activeUsers[username]; ok {
			entry.Deleted = false
			continue
		}
		if entry.Deleted {
			continue
		}
		entry.LastDeltaUplink = entry.CurrentUplink - entry.BaseUplink
		entry.LastDeltaDown = entry.CurrentDownlink - entry.BaseDownlink
		entry.Deleted = true
	}
}

func (t *trafficTracker) applySampleLocked(username string, counters userMetrics) {
	entry, exists := t.entries[username]
	if !exists {
		t.entries[username] = &trafficEntry{
			CurrentUplink:   counters.Uplink,
			CurrentDownlink: counters.Downlink,
		}
		return
	}

	readded := false
	if entry.Deleted {
		pendingUplink := entry.LastDeltaUplink
		pendingDownlink := entry.LastDeltaDown
		entry.BaseUplink = counters.Uplink - pendingUplink
		entry.BaseDownlink = counters.Downlink - pendingDownlink
		entry.LastDeltaUplink = 0
		entry.LastDeltaDown = 0
		entry.Deleted = false
		readded = true
	}

	if !readded && (counters.Uplink < entry.CurrentUplink || counters.Downlink < entry.CurrentDownlink) {
		pendingUplink := entry.CurrentUplink - entry.BaseUplink
		if pendingUplink < 0 {
			pendingUplink = 0
		}
		pendingDownlink := entry.CurrentDownlink - entry.BaseDownlink
		if pendingDownlink < 0 {
			pendingDownlink = 0
		}
		entry.BaseUplink = counters.Uplink - pendingUplink
		entry.BaseDownlink = counters.Downlink - pendingDownlink
	}

	entry.CurrentUplink = counters.Uplink
	entry.CurrentDownlink = counters.Downlink
}

func (t *trafficTracker) UserStats(username, link string, reset bool) *common.StatResponse {
	if reset {
		t.mu.Lock()
		defer t.mu.Unlock()
	} else {
		t.mu.RLock()
		defer t.mu.RUnlock()
	}

	response := &common.StatResponse{Stats: []*common.Stat{}}
	entry, exists := t.entries[username]
	if !exists {
		return response
	}

	response.Stats = append(response.Stats, buildTrafficStats(username, link, entry.deltaUplink(), entry.deltaDownlink())...)
	if reset {
		t.resetEntryLocked(username, entry)
	}
	return response
}

func (t *trafficTracker) UsersStats(link string, reset bool) *common.StatResponse {
	if reset {
		t.mu.Lock()
		defer t.mu.Unlock()
	} else {
		t.mu.RLock()
		defer t.mu.RUnlock()
	}

	response := &common.StatResponse{Stats: make([]*common.Stat, 0, len(t.entries)*2)}
	for username, entry := range t.entries {
		response.Stats = append(response.Stats, buildTrafficStats(username, link, entry.deltaUplink(), entry.deltaDownlink())...)
		if reset {
			t.resetEntryLocked(username, entry)
		}
	}
	return response
}

func (t *trafficTracker) AggregateStats(name, link string, reset bool) *common.StatResponse {
	if reset {
		t.mu.Lock()
		defer t.mu.Unlock()
	} else {
		t.mu.RLock()
		defer t.mu.RUnlock()
	}

	var totalUplink int64
	var totalDownlink int64
	for username, entry := range t.entries {
		totalUplink += entry.deltaUplink()
		totalDownlink += entry.deltaDownlink()
		if reset {
			t.resetEntryLocked(username, entry)
		}
	}

	return &common.StatResponse{
		Stats: buildTrafficStats(name, link, totalUplink, totalDownlink),
	}
}

func (t *trafficTracker) resetEntryLocked(username string, entry *trafficEntry) {
	entry.BaseUplink = entry.CurrentUplink
	entry.BaseDownlink = entry.CurrentDownlink
	if entry.Deleted {
		delete(t.entries, username)
	}
}

func (e *trafficEntry) deltaUplink() int64 {
	delta := e.CurrentUplink - e.BaseUplink
	if delta < 0 {
		return 0
	}
	return delta
}

func (e *trafficEntry) deltaDownlink() int64 {
	delta := e.CurrentDownlink - e.BaseDownlink
	if delta < 0 {
		return 0
	}
	return delta
}

func buildTrafficStats(name, link string, uplink, downlink int64) []*common.Stat {
	if uplink == 0 && downlink == 0 {
		return nil
	}

	stats := make([]*common.Stat, 0, 2)
	if uplink > 0 {
		stats = append(stats, &common.Stat{
			Name:  name,
			Type:  "uplink",
			Link:  link,
			Value: uplink,
		})
	}
	if downlink > 0 {
		stats = append(stats, &common.Stat{
			Name:  name,
			Type:  "downlink",
			Link:  link,
			Value: downlink,
		})
	}
	return stats
}
