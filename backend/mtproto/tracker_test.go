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

// TestSourceSwitchCarriesBoundaryTraffic: both sources count the same telemt
// stats entry (total_octets is from + to), so the bytes counted between the
// last sample of one source and the first of the other are billed once, as
// downlink, in every family.
func TestSourceSwitchCarriesBoundaryTraffic(t *testing.T) {
	tr := newTrafficTracker()
	var users, outbound counters
	poll := func(resp *common.StatResponse, total *counters, want map[string]counters) {
		t.Helper()
		assertTraffic(t, resp, want)
		for _, got := range trafficByName(t, resp) {
			*total = total.plus(got)
		}
	}

	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(100, 200)}))
	poll(tr.UsersStats("mtproto", true), &users, map[string]counters{"u1": {100, 200}})
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(150, 250)}))
	poll(tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), &outbound, map[string]counters{"mtproto": {150, 250}})

	// Metrics to API totals, 50 bytes past 150+250.
	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u1": traffic(0, 450)}))
	poll(tr.UsersStats("mtproto", true), &users, map[string]counters{"u1": {50, 100}})

	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u1": traffic(0, 500)}))
	poll(tr.UsersStats("mtproto", true), &users, map[string]counters{"u1": {0, 50}})
	poll(tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), &outbound, map[string]counters{"mtproto": {0, 100}})

	// API totals to metrics, 30 bytes past 500.
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(210, 320)}))
	poll(tr.UsersStats("mtproto", true), &users, map[string]counters{"u1": {0, 30}})

	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(220, 340)}))
	poll(tr.UsersStats("mtproto", true), &users, map[string]counters{"u1": {10, 20}})
	poll(tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), &outbound, map[string]counters{"mtproto": {10, 50}})

	if users != (counters{160, 400}) || outbound != (counters{160, 400}) {
		t.Errorf("billed users %v, outbound %v; want {160 400} (220+340 bytes) each", users, outbound)
	}
}

// TestSourceSwitchAfterEvictionCountsFromZero: a total below the last
// sample means telemt dropped the stats entry in between and counts from
// zero again.
func TestSourceSwitchAfterEvictionCountsFromZero(t *testing.T) {
	tr := newTrafficTracker()
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(100, 200)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {100, 200}})
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(120, 230)}))

	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u1": traffic(0, 40)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {20, 70}})
	assertTraffic(t, tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), map[string]counters{"mtproto": {120, 270}})

	// The other direction: metrics below the last API total.
	tr.Apply(apiSnapshot(1, map[string]userMetrics{"u1": traffic(0, 90)}))
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(5, 15)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {5, 65}})
	assertTraffic(t, tr.AggregateStats(familyOutbound, "mtproto", "mtproto", true), map[string]counters{"mtproto": {5, 65}})
}

// TestGenerationChangeBeatsSourceChange: a new telemt counts from zero, so
// the whole first sample is new traffic, whatever the source.
func TestGenerationChangeBeatsSourceChange(t *testing.T) {
	tr := newTrafficTracker()
	tr.Apply(metricsSnapshot(1, map[string]userMetrics{"u1": traffic(100, 200)}))
	tr.Apply(apiSnapshot(2, map[string]userMetrics{"u1": traffic(0, 400)}))
	assertTraffic(t, tr.UsersStats("mtproto", true), map[string]counters{"u1": {100, 600}})
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
