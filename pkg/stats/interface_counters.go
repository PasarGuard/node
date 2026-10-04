package stats

import (
	"sync"

	"github.com/pasarguard/node/common"
)

// InterfaceCountersTracker tracks delta and reset state for interface-level RX/TX counters.
type InterfaceCountersTracker struct {
	mu sync.Mutex

	baseRx  int64
	baseTx  int64
	baseSet bool

	usageSet     bool
	usageLastRx  int64
	usageLastTx  int64
	usageTotalRx int64
	usageTotalTx int64
}

// Cumulative preserves observed traffic across interface counter resets without
// changing the legacy reset baseline. Activation includes only traffic since
// the last legacy reset, avoiding double billing during protocol migration.
func (t *InterfaceCountersTracker) Cumulative(rx, tx int64) (int64, int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.usageSet {
		t.usageSet = true
		if t.baseSet {
			t.usageTotalRx = max(0, rx-t.baseRx)
			t.usageTotalTx = max(0, tx-t.baseTx)
		}
	} else {
		if rx >= t.usageLastRx {
			t.usageTotalRx += rx - t.usageLastRx
		} else {
			t.usageTotalRx += max(0, rx)
		}
		if tx >= t.usageLastTx {
			t.usageTotalTx += tx - t.usageLastTx
		} else {
			t.usageTotalTx += max(0, tx)
		}
	}
	t.usageLastRx, t.usageLastTx = rx, tx
	return t.usageTotalRx, t.usageTotalTx
}

func NewInterfaceCountersTracker() *InterfaceCountersTracker {
	return &InterfaceCountersTracker{}
}

// Delta calculates counters relative to the current baseline.
// On first sample, it sets baseline and returns zero.
// If counters roll back (interface reset/restart), it rebases and returns zero.
func (t *InterfaceCountersTracker) Delta(currentRx, currentTx int64, reset bool) (int64, int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.baseSet {
		t.baseRx = currentRx
		t.baseTx = currentTx
		t.baseSet = true
	}

	if currentRx < t.baseRx || currentTx < t.baseTx {
		t.baseRx = currentRx
		t.baseTx = currentTx
	}

	deltaRx := currentRx - t.baseRx
	deltaTx := currentTx - t.baseTx

	if reset {
		t.baseRx = currentRx
		t.baseTx = currentTx
	}

	return deltaRx, deltaTx
}

func buildDeltaStats(name, link string, rx, tx int64) []*common.Stat {
	if rx == 0 && tx == 0 {
		return nil
	}

	stats := make([]*common.Stat, 0, 2)
	if tx > 0 {
		stats = append(stats, &common.Stat{
			Name:  name,
			Type:  "uplink",
			Link:  link,
			Value: tx,
		})
	}
	if rx > 0 {
		stats = append(stats, &common.Stat{
			Name:  name,
			Type:  "downlink",
			Link:  link,
			Value: rx,
		})
	}

	return stats
}

func BuildInterfaceStats(name, link string, rx, tx int64) []*common.Stat {
	return buildDeltaStats(name, link, rx, tx)
}
