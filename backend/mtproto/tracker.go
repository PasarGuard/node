package mtproto

import (
	"log"
	"sync"
	"time"

	"github.com/pasarguard/node/common"
)

// statFamily is a group of stats the panel reads and resets on its own
// schedule (users every 10 s, outbounds every 30 s). Like xray's separate
// counters, each family keeps its own baseline per user, so resetting one
// family never hides traffic from another.
type statFamily uint8

const (
	familyUsers statFamily = iota
	familyOutbound
	familyInbound
	familyCount
)

// counterSource is where a snapshot's per-user counters come from.
type counterSource uint8

const (
	// sourceMetrics is telemt's per-user Prometheus counters, one per
	// direction.
	sourceMetrics counterSource = iota
	// sourceAPITotals is total_octets from GET /v1/users, used while telemt
	// suppresses per-user series (more than 4096 users with stats or
	// configured users). It sums both directions, so it is reported as
	// downlink with uplink 0.
	sourceAPITotals
)

// absentEntryTTL is how long the tracker keeps a user that no snapshot
// reports. telemt keeps a user's counters after the user leaves its config
// until they have been idle for 24 h, so a user re-added sooner comes back
// with its old total, which must not be billed again.
const absentEntryTTL = 25 * time.Hour

// trafficSnapshot is one read of telemt's per-user counters. Generation is
// the telemt process (processManager.Generation) the counters came from.
type trafficSnapshot struct {
	Users      map[string]userMetrics
	Source     counterSource
	Generation uint64
}

// counters is a byte count per direction.
type counters struct {
	Up   int64
	Down int64
}

// trafficEntry follows one user's telemt counters. Current is the latest
// sample, and Base[f] the point family f last reported up to, so the
// family's unreported traffic is Current - Base[f].
type trafficEntry struct {
	Current     counters
	Base        [familyCount]counters
	Source      counterSource
	Generation  uint64
	AbsentSince time.Time // zero while snapshots report the user
}

// trafficTracker turns telemt's cumulative per-user counters into the
// deltas each stat family reports. It follows every user telemt reports,
// desired or not: telemt keeps counting a removed user until it forgets the
// user's stats.
type trafficTracker struct {
	mu      sync.RWMutex
	entries map[string]*trafficEntry
	// retired holds the unreported outbound and inbound traffic of dropped
	// entries.
	retired [familyCount]counters
	source  counterSource
	applied bool
	now     func() time.Time
}

func newTrafficTracker() *trafficTracker {
	return &trafficTracker{
		entries: make(map[string]*trafficEntry),
		now:     time.Now,
	}
}

// Apply takes a snapshot. A user missing from it is not sampled: its
// counters are unknown, not zero. Snapshots must be applied in the order
// they were read.
func (t *trafficTracker) Apply(s trafficSnapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.applied && s.Source != t.source {
		logSourceChange(s.Source)
	}
	t.applied = true
	t.source = s.Source

	for username, metrics := range s.Users {
		sample := counters{Up: metrics.Uplink, Down: metrics.Downlink}
		entry, exists := t.entries[username]
		if !exists {
			// telemt counts a user from zero, and keeps counting while it
			// reports the user, so the whole counter is new traffic.
			t.entries[username] = &trafficEntry{Current: sample, Source: s.Source, Generation: s.Generation}
			continue
		}

		switch {
		case entry.Generation != s.Generation:
			// A new telemt process counts from zero, whichever source.
			entry.carryPending(counters{})
		case entry.Source != s.Source:
			entry.carryAcrossSource(sample)
		case sample.Up < entry.Current.Up || sample.Down < entry.Current.Down:
			// telemt dropped the user's stats after 24 h idle and counts
			// from zero again.
			entry.carryPending(counters{})
		}
		entry.Current = sample
		entry.Source = s.Source
		entry.Generation = s.Generation
		entry.AbsentSince = time.Time{}
	}

	now := t.now()
	for username, entry := range t.entries {
		if _, present := s.Users[username]; present {
			continue
		}
		if entry.AbsentSince.IsZero() {
			entry.AbsentSince = now
		}
		if now.Sub(entry.AbsentSince) < absentEntryTTL || entry.delta(familyUsers) != (counters{}) {
			continue
		}
		// Users are reported one by one, so a user is dropped only once
		// reported; the aggregates keep its pending traffic.
		for _, family := range []statFamily{familyOutbound, familyInbound} {
			t.retired[family] = t.retired[family].plus(entry.delta(family))
		}
		delete(t.entries, username)
	}
}

func logSourceChange(source counterSource) {
	if source == sourceAPITotals {
		log.Println("mtproto: telemt suppresses per-user metrics (more than 4096 users with stats or configured users); " +
			"counting traffic from its user API totals, reported as downlink")
		return
	}
	log.Println("mtproto: telemt exports per-user metrics again; counting traffic from them")
}

// carryAcrossSource rebases every family onto sample from the other source.
// Both sources count the same telemt stats entry (total_octets is
// octets_from_client + octets_to_client), so the bytes counted since the
// last sample are known as a total: they are credited as downlink.
func (e *trafficEntry) carryAcrossSource(sample counters) {
	increment := sample.Up + sample.Down - (e.Current.Up + e.Current.Down)
	if increment < 0 {
		// telemt dropped the stats entry in between and counts from zero
		// again.
		e.carryPending(counters{})
		return
	}
	e.carryPending(counters{Up: sample.Up, Down: sample.Down - increment})
}

// carryPending rebases every family onto a counter that now stands at start,
// keeping each family's unreported traffic: Base = start - pending.
func (e *trafficEntry) carryPending(start counters) {
	for family := range familyCount {
		pending := e.delta(family)
		e.Base[family] = counters{Up: start.Up - pending.Up, Down: start.Down - pending.Down}
	}
}

// delta is family f's unreported traffic, never negative.
func (e *trafficEntry) delta(f statFamily) counters {
	return counters{
		Up:   max(0, e.Current.Up-e.Base[f].Up),
		Down: max(0, e.Current.Down-e.Base[f].Down),
	}
}

func (c counters) plus(other counters) counters {
	return counters{Up: c.Up + other.Up, Down: c.Down + other.Down}
}

// lock takes the write lock when reset changes baselines, else the read lock,
// and returns the matching unlock.
func (t *trafficTracker) lock(reset bool) func() {
	if reset {
		t.mu.Lock()
		return t.mu.Unlock
	}
	t.mu.RLock()
	return t.mu.RUnlock
}

// UserStats reports one user's traffic. A reset covers only that user.
func (t *trafficTracker) UserStats(username, link string, reset bool) *common.StatResponse {
	defer t.lock(reset)()

	response := &common.StatResponse{Stats: []*common.Stat{}}
	entry, exists := t.entries[username]
	if !exists {
		return response
	}
	response.Stats = append(response.Stats, buildTrafficStats(username, link, entry.delta(familyUsers))...)
	if reset {
		entry.Base[familyUsers] = entry.Current
	}
	return response
}

// UsersStats reports every user with traffic. A reset covers the users it
// reported.
func (t *trafficTracker) UsersStats(link string, reset bool) *common.StatResponse {
	defer t.lock(reset)()

	response := &common.StatResponse{Stats: make([]*common.Stat, 0, len(t.entries)*2)}
	for username, entry := range t.entries {
		delta := entry.delta(familyUsers)
		if delta == (counters{}) {
			continue
		}
		response.Stats = append(response.Stats, buildTrafficStats(username, link, delta)...)
		if reset {
			entry.Base[familyUsers] = entry.Current
		}
	}
	return response
}

// AggregateStats reports the traffic of all users as one stat for family f,
// which must be familyOutbound or familyInbound.
func (t *trafficTracker) AggregateStats(f statFamily, name, link string, reset bool) *common.StatResponse {
	response := &common.StatResponse{Stats: []*common.Stat{}}
	if f != familyOutbound && f != familyInbound {
		return response
	}
	defer t.lock(reset)()

	total := t.retired[f]
	for _, entry := range t.entries {
		total = total.plus(entry.delta(f))
		if reset {
			entry.Base[f] = entry.Current
		}
	}
	if reset {
		t.retired[f] = counters{}
	}
	response.Stats = append(response.Stats, buildTrafficStats(name, link, total)...)
	return response
}

func buildTrafficStats(name, link string, traffic counters) []*common.Stat {
	stats := make([]*common.Stat, 0, 2)
	if traffic.Up > 0 {
		stats = append(stats, &common.Stat{Name: name, Type: "uplink", Link: link, Value: traffic.Up})
	}
	if traffic.Down > 0 {
		stats = append(stats, &common.Stat{Name: name, Type: "downlink", Link: link, Value: traffic.Down})
	}
	return stats
}
