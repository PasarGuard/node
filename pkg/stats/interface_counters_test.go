package stats

import (
	"sync"
	"testing"
)

func TestInterfaceCountersTrackerFirstSampleIsZero(t *testing.T) {
	tracker := NewInterfaceCountersTracker()

	rx, tx := tracker.Delta(100, 200, false)
	if rx != 0 || tx != 0 {
		t.Fatalf("expected zero delta on first sample, got rx=%d tx=%d", rx, tx)
	}
}

func TestInterfaceCountersTrackerNormalDelta(t *testing.T) {
	tracker := NewInterfaceCountersTracker()
	tracker.Delta(100, 200, false)

	rx, tx := tracker.Delta(130, 260, false)
	if rx != 30 || tx != 60 {
		t.Fatalf("unexpected delta, got rx=%d tx=%d want rx=30 tx=60", rx, tx)
	}
}

func TestInterfaceCountersTrackerReset(t *testing.T) {
	tracker := NewInterfaceCountersTracker()
	tracker.Delta(100, 200, false)

	rx, tx := tracker.Delta(150, 260, true)
	if rx != 50 || tx != 60 {
		t.Fatalf("unexpected reset delta, got rx=%d tx=%d want rx=50 tx=60", rx, tx)
	}

	rx, tx = tracker.Delta(170, 290, false)
	if rx != 20 || tx != 30 {
		t.Fatalf("unexpected post-reset delta, got rx=%d tx=%d want rx=20 tx=30", rx, tx)
	}
}

func TestInterfaceCountersTrackerRollbackRebases(t *testing.T) {
	tracker := NewInterfaceCountersTracker()
	tracker.Delta(200, 300, false)

	rx, tx := tracker.Delta(150, 250, false)
	if rx != 0 || tx != 0 {
		t.Fatalf("expected zero after rollback rebase, got rx=%d tx=%d", rx, tx)
	}

	rx, tx = tracker.Delta(170, 260, false)
	if rx != 20 || tx != 10 {
		t.Fatalf("unexpected delta after rollback rebase, got rx=%d tx=%d want rx=20 tx=10", rx, tx)
	}
}

func TestInterfaceCountersTrackerConcurrentSafety(t *testing.T) {
	tracker := NewInterfaceCountersTracker()
	tracker.Delta(0, 0, false)

	var wg sync.WaitGroup
	for i := 1; i <= 200; i++ {
		wg.Add(1)
		go func(v int64) {
			defer wg.Done()
			_, _ = tracker.Delta(v, v*2, v%25 == 0)
		}(int64(i))
	}
	wg.Wait()
}

func TestBuildInterfaceStats(t *testing.T) {
	stats := BuildInterfaceStats("wg0", "wg0", 15, 9)
	if len(stats) != 2 {
		t.Fatalf("expected 2 stats, got %d", len(stats))
	}

	if stats[0].GetLink() != "wg0" || stats[1].GetLink() != "wg0" {
		t.Fatalf("expected link=wg0 for all entries")
	}
}
