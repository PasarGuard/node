package mtproto

import (
	"maps"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
)

func traffic(up, down int64) userMetrics {
	return userMetrics{Uplink: up, Downlink: down}
}

func metricsSnapshot(generation uint64, users map[string]userMetrics) trafficSnapshot {
	return trafficSnapshot{Users: users, Source: sourceMetrics, Generation: generation}
}

func apiSnapshot(generation uint64, users map[string]userMetrics) trafficSnapshot {
	return trafficSnapshot{Users: users, Source: sourceAPITotals, Generation: generation}
}

// trafficByName sums a response's uplink and downlink values per stat name.
func trafficByName(t *testing.T, resp *common.StatResponse) map[string]counters {
	t.Helper()
	got := make(map[string]counters)
	for _, stat := range resp.GetStats() {
		total := got[stat.GetName()]
		switch stat.GetType() {
		case "uplink":
			total.Up += stat.GetValue()
		case "downlink":
			total.Down += stat.GetValue()
		default:
			t.Errorf("unexpected stat type %q", stat.GetType())
		}
		got[stat.GetName()] = total
	}
	return got
}

// assertTraffic checks that resp reports exactly want: every name with its
// uplink and downlink, and no other name.
func assertTraffic(t *testing.T, resp *common.StatResponse, want map[string]counters) {
	t.Helper()
	if got := trafficByName(t, resp); !maps.Equal(got, want) {
		t.Errorf("stats = %v, want %v", got, want)
	}
}

func TestFamiliesHaveIndependentBaselines(t *testing.T) {
	tr := newTrafficTracker()
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(100, 200)}))

	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {100, 200}})
	assertTraffic(t, tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), map[string]counters{"mtproto": {100, 200}})
	assertTraffic(t, tr.AggregateStats(familyInbound, "mtproto", "mtproto", true), map[string]counters{"mtproto": {100, 200}})

	// The other order: an outbound poll first must not hide user traffic.
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(150, 260)}))
	assertTraffic(t, tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), map[string]counters{"mtproto": {50, 60}})
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {50, 60}})
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{})
	assertTraffic(t, tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), map[string]counters{})
	assertTraffic(t, tr.AggregateStats(familyInbound, "mtproto", "mtproto", true), map[string]counters{"mtproto": {50, 60}})
}

func TestUserStatResetsOnlyThatUser(t *testing.T) {
	tr := newTrafficTracker()
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(10, 20), "u2": traffic(30, 40)}))

	assertTraffic(t, tr.UserStats("u1", "mtproto", true), map[string]counters{"u1": {10, 20}})
	assertTraffic(t, tr.UserStats("u1", "mtproto", true), map[string]counters{})
	assertTraffic(t, tr.UsersStats("mtproto", false), map[string]counters{"u2": {30, 40}})
	assertTraffic(t, tr.AggregateStats(familyOutbound, "mtproto", "mtproto", false), map[string]counters{"mtproto": {40, 60}})
}

func TestAbsentUserIsNotACounterReset(t *testing.T) {
	tr := newTrafficTracker()
	var reported counters
	report := func() {
		t.Helper()
		got := trafficByName(t, tr.UsersStats("mtproto", true))
		reported.Up += got["u1"].Up
		reported.Down += got["u1"].Down
	}

	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(1000, 100), "u2": traffic(1, 1)}))
	report()
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u2": traffic(2, 2)}))
	report()
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(1500, 150), "u2": traffic(3, 3)}))
	report()

	if reported != (counters{1500, 150}) {
		t.Errorf("u1 reported %v in total, want {1500 150}", reported)
	}
	assertTraffic(t, tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), map[string]counters{"mtproto": {1503, 153}})
}

func TestGenerationChangeKeepsPendingDelta(t *testing.T) {
	tr := newTrafficTracker()
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(500, 50)}))
	// telemt restarted: its counters start from zero again.
	tr.Apply(metricsSnapshot(2, map[string]userMetrics{"u1": traffic(100, 10)}))

	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {600, 60}})
	assertTraffic(t, tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), map[string]counters{"mtproto": {600, 60}})

	tr.Apply(metricsSnapshot(2, map[string]userMetrics{"u1": traffic(130, 15)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {30, 5}})
}

// TestCounterDecreaseCarriesPending: a counter that goes down within one
// telemt process means telemt dropped the user's stats entry (24 h idle) and
// counts from zero again. Moved from the old tracker test, with the traffic
// after the decrease now counted too.
func TestCounterDecreaseCarriesPending(t *testing.T) {
	tr := newTrafficTracker()

	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"alice": traffic(0, 0)}))
	assertTraffic(t, tr.UsersStats("mtproto", false), map[string]counters{})

	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"alice": traffic(50, 60)}))
	assertTraffic(t, tr.UsersStats("mtproto", false), map[string]counters{"alice": {50, 60}})

	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"alice": traffic(5, 3)}))
	assertTraffic(t, tr.UsersStats("mtproto", false), map[string]counters{"alice": {55, 63}})

	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"alice": traffic(25, 13)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"alice": {75, 73}})
	assertTraffic(t, tr.UsersStats("mtproto", false), map[string]counters{})

	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"alice": traffic(35, 20)}))
	assertTraffic(t, tr.UsersStats("mtproto", false), map[string]counters{"alice": {10, 7}})
}

// TestSourceChangeReseeds: API totals sum both directions, so switching
// sources must neither bill a counter twice nor lose what was pending.
func TestSourceChangeReseeds(t *testing.T) {
	tr := newTrafficTracker()
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(100, 200)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {100, 200}})
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(150, 250)}))

	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u1": traffic(0, 400)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {50, 50}})

	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u1": traffic(0, 500)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {0, 100}})

	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(200, 300)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{})

	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(210, 320)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {10, 20}})
	assertTraffic(t, tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), map[string]counters{"mtproto": {160, 370}})
}

// TestAbsentEntryIsKeptUntilTelemtForgetsIt: telemt keeps a removed user's
// counters until they sit idle for 24 h, and its user list omits users not in
// the config. A user re-added within that time comes back with its old total.
func TestAbsentEntryIsKeptUntilTelemtForgetsIt(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tr := newTrafficTracker()
	tr.now = func() time.Time { return now }

	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u1": traffic(0, 1000), "u2": traffic(0, 5)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {0, 1000}, "u2": {0, 5}})

	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u2": traffic(0, 5)}))
	now = now.Add(time.Hour)
	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u1": traffic(0, 1200), "u2": traffic(0, 5)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {0, 200}})

	// Removed for longer than telemt keeps idle counters: the entry goes,
	// and its unreported outbound traffic stays in the aggregate.
	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u2": traffic(0, 5)}))
	now = now.Add(absentEntryTTL)
	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u2": traffic(0, 5)}))
	tr.mu.RLock()
	_, kept := tr.entries["u1"]
	tr.mu.RUnlock()
	if kept {
		t.Fatal("u1 is still tracked after being absent for absentEntryTTL")
	}

	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u1": traffic(0, 300), "u2": traffic(0, 5)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {0, 300}})
	assertTraffic(t, tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), map[string]counters{"mtproto": {0, 1505}})
}

// TestAbsentEntryWithPendingTrafficIsKept: an entry is never dropped while
// its user traffic is unreported.
func TestAbsentEntryWithPendingTrafficIsKept(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tr := newTrafficTracker()
	tr.now = func() time.Time { return now }

	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(10, 20)}))
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{}))
	now = now.Add(2 * absentEntryTTL)
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{}))

	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {10, 20}})
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{}))
	tr.mu.RLock()
	remaining := len(tr.entries)
	tr.mu.RUnlock()
	if remaining != 0 {
		t.Errorf("%d entries remain after the pending traffic was reported", remaining)
	}
}
