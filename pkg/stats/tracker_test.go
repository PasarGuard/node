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

func TestStatsTracker_RemoveStatsStoresPendingLastDelta(t *testing.T) {
	tracker := New()
	updateSample(tracker, "key1", "user1@example.com", 1000, 2000, "1.2.3.4")
	tracker.RemoveStats("key1")

	entries := tracker.GetStatsEntries([]string{"key1"})
	entry, ok := entries["key1"]
	if !ok {
		t.Fatal("expected entry to exist")
	}
	if entry.LastDeltaRx != 1000 {
		t.Fatalf("expected LastDeltaRx=1000, got %d", entry.LastDeltaRx)
	}
	if entry.LastDeltaTx != 2000 {
		t.Fatalf("expected LastDeltaTx=2000, got %d", entry.LastDeltaTx)
	}
}

func TestStatsTracker_ReaddAfterDeletePreservesPendingDelta(t *testing.T) {
	tracker := New()
	ctx := context.Background()

	updateSample(tracker, "key1", "user1@example.com", 1000, 2000, "1.2.3.4")
	tracker.RemoveStats("key1")

	// Simulate a re-added key with restarted counters.
	updateSample(tracker, "key1", "user1@example.com", 100, 200, "1.2.3.4")

	resp := tracker.GetStats(ctx, []string{"key1"}, false)
	for _, s := range resp.Stats {
		if s.Type == "downlink" && s.Value != 1000 {
			t.Errorf("Expected preserved rx=1000, got %d", s.Value)
		}
		if s.Type == "uplink" && s.Value != 2000 {
			t.Errorf("Expected preserved tx=2000, got %d", s.Value)
		}
	}

	tracker.GetStats(ctx, []string{"key1"}, true)

	resp = tracker.GetStats(ctx, []string{"key1"}, false)
	if len(resp.Stats) != 0 {
		t.Errorf("Expected 0 stats after reset, got %d", len(resp.Stats))
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
