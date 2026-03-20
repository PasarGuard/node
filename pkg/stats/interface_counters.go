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
