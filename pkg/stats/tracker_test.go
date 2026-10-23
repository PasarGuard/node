package stats

import (
	"context"
	"testing"
	"time"
)

func updateSample(tracker *Tracker, publicKey, email string, rx, tx int64, endpointIP string) {
	tracker.UpdateStatsBatch([]Sample{
		{
			PublicKey:  publicKey,
			Email:      email,
			Rx:         rx,
			Tx:         tx,
			EndpointIP: endpointIP,
		},
	})
}

func TestStatsTracker_GetStats(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	updateSample(tracker, "key1", "user@example.com", 1000, 2000, "1.2.3.4")

	resp := tracker.GetStats(ctx, []string{"key1"}, false)
	if len(resp.Stats) != 2 {
		t.Fatalf("Expected 2 stats, got %d", len(resp.Stats))
	}

	for _, s := range resp.Stats {
		if s.Type == "downlink" && s.Value != 1000 {
			t.Errorf("Expected rx=1000, got %d", s.Value)
		}
		if s.Type == "uplink" && s.Value != 2000 {
			t.Errorf("Expected tx=2000, got %d", s.Value)
		}
	}
}

func TestStatsTracker_GetStatsReset(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	updateSample(tracker, "key1", "user@example.com", 1000, 2000, "1.2.3.4")
	updateSample(tracker, "key1", "user@example.com", 2000, 4000, "1.2.3.4")

	resp := tracker.GetStats(ctx, []string{"key1"}, true)
	for _, s := range resp.Stats {
		if s.Type == "downlink" && s.Value != 2000 {
			t.Errorf("Expected rx=2000, got %d", s.Value)
		}
		if s.Type == "uplink" && s.Value != 4000 {
			t.Errorf("Expected tx=4000, got %d", s.Value)
		}
	}

	resp2 := tracker.GetStats(ctx, []string{"key1"}, false)
	for _, s := range resp2.Stats {
		if s.Value != 0 {
			t.Errorf("Expected 0 after reset, got %d", s.Value)
		}
	}
}

func TestStatsTracker_GetUsersStats(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	updateSample(tracker, "key1", "user1@example.com", 1000, 2000, "1.2.3.4")
	updateSample(tracker, "key2", "user2@example.com", 3000, 4000, "1.2.3.5")

	resp := tracker.GetUsersStats(ctx, false)
	if len(resp.Stats) != 4 {
		t.Fatalf("Expected 4 stats, got %d", len(resp.Stats))
	}
}

func TestStatsTracker_RemoveStatsMarksDeletedAndKeepsDeltaUntilReset(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	updateSample(tracker, "key1", "user@example.com", 1000, 2000, "1.2.3.4")
	entriesBefore := tracker.GetStatsEntries([]string{"key1"})
	if entriesBefore["key1"].LastActiveTime.IsZero() {
		t.Fatal("expected LastActiveTime to be set before removal")
	}

	tracker.RemoveStats("key1")

	entriesAfter := tracker.GetStatsEntries([]string{"key1"})
	entry, ok := entriesAfter["key1"]
	if !ok {
		t.Fatal("expected entry to remain after RemoveStats")
	}
	if !entry.IsDeleted {
		t.Fatal("expected entry to be marked deleted")
	}
	if !entry.LastActiveTime.IsZero() {
		t.Fatal("expected LastActiveTime to be cleared on RemoveStats")
	}

	resp := tracker.GetStats(ctx, []string{"key1"}, false)
	if len(resp.Stats) != 2 {
		t.Fatalf("expected stats to remain reportable until reset, got %d", len(resp.Stats))
	}
}

func TestStatsTracker_ClearAllStats(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	updateSample(tracker, "key1", "user1@example.com", 1000, 2000, "1.2.3.4")
	tracker.ClearAllStats()

	resp := tracker.GetUsersStats(ctx, false)
	if len(resp.Stats) != 0 {
		t.Errorf("Expected 0 stats after clear, got %d", len(resp.Stats))
	}
}

func TestStatsTracker_RemoveStatsEntryDeletedOnReset(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	updateSample(tracker, "key1", "user@example.com", 1000, 2000, "1.2.3.4")
	tracker.RemoveStats("key1")

	// Reset should include this peer's pending traffic and then delete the entry.
	resp := tracker.GetStats(ctx, []string{"key1"}, true)
	if len(resp.Stats) != 2 {
		t.Fatalf("expected 2 stats in reset response, got %d", len(resp.Stats))
	}

	entries := tracker.GetStatsEntries([]string{"key1"})
	if _, exists := entries["key1"]; exists {
		t.Fatal("expected deleted entry to be removed after reset")
	}
}

func TestStatsTracker_CleanupDeletedEntriesSafetyNet(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	updateSample(tracker, "key1", "user@example.com", 1000, 2000, "1.2.3.4")

	// First reset, so delta becomes zero.
	tracker.GetStats(ctx, []string{"key1"}, true)

	// Mark deleted with zero delta and remove through periodic cleanup.
	tracker.RemoveStats("key1")
	tracker.CleanupDeletedEntries()

	entries := tracker.GetStatsEntries([]string{"key1"})
	if _, exists := entries["key1"]; exists {
		t.Fatal("expected zero-delta deleted entry to be cleaned up")
	}
}

func TestStatsTracker_ZeroDeltaSkipping(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	// Initial usage
	updateSample(tracker, "key1", "user@example.com", 1000, 2000, "1.2.3.4")

	// Reset
	tracker.GetStats(ctx, []string{"key1"}, true)

	// No change
	resp := tracker.GetStats(ctx, []string{"key1"}, false)
	if len(resp.Stats) != 0 {
		t.Errorf("Expected 0 stats for zero delta, got %d", len(resp.Stats))
	}
}

func TestStatsTracker_RemoveStatsKeepsPendingDelta(t *testing.T) {
	tracker := New()
	updateSample(tracker, "key1", "user1@example.com", 1000, 2000, "1.2.3.4")
	tracker.RemoveStats("key1")

	if rx, tx := pullTotals(tracker); rx != 1000 || tx != 2000 {
		t.Fatalf("expected pending 1000/2000 after RemoveStats, got %d/%d", rx, tx)
	}
}

// A re-added key is a new kernel peer whose counters restarted at zero, so its first sample
// (100/200) is new traffic and is reported on top of the delta still pending from before the
// removal (1000/2000). This test used to expect only 1000/2000, which dropped those bytes.
func TestStatsTracker_ReaddAfterDeletePreservesPendingDelta(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	updateSample(tracker, "key1", "user1@example.com", 1000, 2000, "1.2.3.4")
	tracker.RemoveStats("key1")

	// Simulate a re-added key with restarted counters.
	updateSample(tracker, "key1", "user1@example.com", 100, 200, "1.2.3.4")

	resp := tracker.GetStats(ctx, []string{"key1"}, false)
	for _, s := range resp.Stats {
		if s.Type == "downlink" && s.Value != 1100 {
			t.Errorf("Expected pending plus new rx=1100, got %d", s.Value)
		}
		if s.Type == "uplink" && s.Value != 2200 {
			t.Errorf("Expected pending plus new tx=2200, got %d", s.Value)
		}
	}

	tracker.GetStats(ctx, []string{"key1"}, true)

	resp = tracker.GetStats(ctx, []string{"key1"}, false)
	if len(resp.Stats) != 0 {
		t.Errorf("Expected 0 stats after reset, got %d", len(resp.Stats))
	}
}

// pullTotals reads and resets every entry like the panel's usage job, returning rx/tx totals.
func pullTotals(tracker *Tracker) (rx, tx int64) {
	for _, s := range tracker.GetUsersStats(context.Background(), true).Stats {
		switch s.Type {
		case "downlink":
			rx += s.Value
		case "uplink":
			tx += s.Value
		}
	}
	return rx, tx
}

func TestStatsTracker_ReaddAfterReportedDeleteCountsNewTraffic(t *testing.T) {
	tracker := New()

	updateSample(tracker, "key1", "user1@example.com", 1000, 1000, "1.2.3.4")
	pullTotals(tracker)
	tracker.RemoveStats("key1") // nothing pending, entry kept until cleanup

	updateSample(tracker, "key1", "user1@example.com", 300, 400, "1.2.3.4")
	if rx, tx := pullTotals(tracker); rx != 300 || tx != 400 {
		t.Fatalf("expected the re-added peer's 300/400 to be reported, got %d/%d", rx, tx)
	}
}

// A counter that goes down without a mark (peer re-created outside the node's own syncs)
// is still a reset: keep what was pending and count the new counter in full.
func TestStatsTracker_CounterRollbackKeepsPendingAndNewTraffic(t *testing.T) {
	tracker := New()

	updateSample(tracker, "key1", "user1@example.com", 1000, 1000, "1.2.3.4")
	pullTotals(tracker)
	updateSample(tracker, "key1", "user1@example.com", 1500, 1600, "1.2.3.4")
	updateSample(tracker, "key1", "user1@example.com", 200, 300, "1.2.3.4")

	if rx, tx := pullTotals(tracker); rx != 700 || tx != 900 {
		t.Fatalf("expected pending 500/600 plus new 200/300, got %d/%d", rx, tx)
	}
}

// After a reset the new counter can pass the old one before the next sample, which looks like
// normal growth. Only an explicit mark from the backend can tell the two apart.
func TestStatsTracker_MarkCounterResetCountsNewCounterPastOldValue(t *testing.T) {
	tracker := New()

	updateSample(tracker, "key1", "user1@example.com", 1000, 1000, "1.2.3.4")
	pullTotals(tracker)
	updateSample(tracker, "key1", "user1@example.com", 1500, 1500, "1.2.3.4")

	tracker.MarkCounterReset([]string{"key1", "unknown"})
	if entries := tracker.GetStatsEntries([]string{"unknown"}); len(entries) != 0 {
		t.Fatal("MarkCounterReset must not create entries for unknown keys")
	}

	updateSample(tracker, "key1", "user1@example.com", 5000, 5000, "1.2.3.4")
	if rx, tx := pullTotals(tracker); rx != 5500 || tx != 5500 {
		t.Fatalf("expected pending 500 plus new 5000, got %d/%d", rx, tx)
	}
}

// Every byte a peer moves is reported exactly once across pulls, marked resets, unmarked
// rollbacks, repeated marks and remove/re-add, whatever order they come in.
func TestStatsTracker_CounterResetsReportEachByteOnce(t *testing.T) {
	tracker := New()
	var counter, moved, reported int64

	sample := func(add int64) {
		counter += add
		moved += add
		updateSample(tracker, "key1", "user1@example.com", counter, counter, "1.2.3.4")
	}
	pull := func() {
		rx, tx := pullTotals(tracker)
		if rx != tx {
			t.Fatalf("rx %d and tx %d diverged", rx, tx)
		}
		reported += rx
	}
	reset := func() { counter = 0 }

	sample(1000)
	pull()
	sample(500)
	reset()
	tracker.MarkCounterReset([]string{"key1"})
	pull()
	sample(200)
	sample(0)
	pull()
	pull()
	sample(250)
	reset()
	tracker.MarkCounterReset([]string{"key1"})
	tracker.MarkCounterReset([]string{"key1"})
	sample(4000)
	sample(10)
	reset()
	sample(30) // unmarked rollback
	tracker.RemoveStats("key1")
	reset()
	sample(70) // re-added before the pull
	pull()
	tracker.RemoveStats("key1")
	reset()
	sample(5) // re-added after everything was reported
	pull()

	if reported != moved {
		t.Fatalf("reported %d bytes, peer moved %d", reported, moved)
	}
}

func TestStatsTracker_AnyActiveSince(t *testing.T) {
	tracker := New()

	updateSample(tracker, "key1", "user@example.com", 100, 0, "1.2.3.4")

	if !tracker.AnyActiveSince([]string{"key1"}, time.Now().Add(-time.Hour)) {
		t.Fatal("expected key to be active for old cutoff")
	}

	if tracker.AnyActiveSince([]string{"key1"}, time.Now().Add(time.Hour)) {
		t.Fatal("did not expect key to be active for future cutoff")
	}
}

func TestStatsTracker_EndpointActivityReturnsNewestPerIP(t *testing.T) {
	tracker := New()

	updateSample(tracker, "key1", "user1@example.com", 100, 0, "1.1.1.1")
	updateSample(tracker, "key2", "user2@example.com", 100, 0, "1.1.1.1")
	updateSample(tracker, "key3", "user3@example.com", 100, 0, "2.2.2.2")

	now := time.Now()
	tracker.mu.Lock()
	tracker.stats["key1"].LastActiveTime = now.Add(-10 * time.Second)
	tracker.stats["key2"].LastActiveTime = now
	tracker.stats["key3"].LastActiveTime = now.Add(-5 * time.Second)
	tracker.mu.Unlock()

	activity := tracker.EndpointActivity([]string{"key1", "key2", "key3", "missing"})
	if len(activity) != 2 {
		t.Fatalf("expected 2 endpoint entries, got %d", len(activity))
	}

	if got := activity["1.1.1.1"]; got != now.Unix() {
		t.Fatalf("expected newest timestamp for 1.1.1.1, got %d", got)
	}
	if got := activity["2.2.2.2"]; got != now.Add(-5*time.Second).Unix() {
		t.Fatalf("unexpected timestamp for 2.2.2.2: %d", got)
	}
}

func TestStatsTracker_UpdateStatsBatch(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	tracker.UpdateStatsBatch([]Sample{
		{
			PublicKey:  "key1",
			Email:      "user1@example.com",
			Rx:         1000,
			Tx:         2000,
			EndpointIP: "1.1.1.1",
		},
		{
			PublicKey:  "key2",
			Email:      "user2@example.com",
			Rx:         3000,
			Tx:         4000,
			EndpointIP: "2.2.2.2",
		},
	})

	resp := tracker.GetUsersStats(ctx, false)
	if len(resp.Stats) != 4 {
		t.Fatalf("expected 4 stats, got %d", len(resp.Stats))
	}
}

func TestStatsTracker_UpdateStatsBatchDuplicateKeyLastWins(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	tracker.UpdateStatsBatch([]Sample{
		{
			PublicKey:  "key1",
			Email:      "user1@example.com",
			Rx:         100,
			Tx:         200,
			EndpointIP: "1.1.1.1",
		},
		{
			PublicKey:  "key1",
			Email:      "user1@example.com",
			Rx:         500,
			Tx:         600,
			EndpointIP: "3.3.3.3",
		},
	})

	resp := tracker.GetStats(ctx, []string{"key1"}, false)
	if len(resp.Stats) != 2 {
		t.Fatalf("expected 2 stats, got %d", len(resp.Stats))
	}

	entry := tracker.GetStatsEntries([]string{"key1"})["key1"]
	if entry == nil {
		t.Fatal("expected key1 entry")
	}
	if entry.CurrentRx != 500 || entry.CurrentTx != 600 {
		t.Fatalf("expected current counters 500/600, got %d/%d", entry.CurrentRx, entry.CurrentTx)
	}
	if entry.EndpointIP != "3.3.3.3" {
		t.Fatalf("expected endpoint 3.3.3.3, got %s", entry.EndpointIP)
	}
}

func TestStatsTracker_UpdateStatsBatchEmptyNoop(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	tracker.UpdateStatsBatch(nil)
	tracker.UpdateStatsBatch([]Sample{})

	resp := tracker.GetUsersStats(ctx, false)
	if len(resp.Stats) != 0 {
		t.Fatalf("expected 0 stats after empty batch updates, got %d", len(resp.Stats))
	}
}
