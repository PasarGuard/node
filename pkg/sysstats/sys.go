package sysstats

import (
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/pasarguard/node/common"
)

type bandwidthState struct {
	lastRxBytes uint64
	lastTxBytes uint64
	lastTime    time.Time
}

var (
	bwMu          sync.Mutex
	bwState       bandwidthState
	bwInitialized bool
)

func GetSystemStats() (*common.SystemStatsResponse, error) {
	stats := &common.SystemStatsResponse{}

	vm, err := mem.VirtualMemory()
	if err != nil {
		return stats, err
	}
	stats.MemTotal = vm.Total
	stats.MemUsed = vm.Used

	cores, err := cpu.Counts(true)
	if err != nil {
		return stats, err
	}
	stats.CpuCores = uint64(cores)

	percentages, err := cpu.Percent(time.Second, false)
	if err != nil {
		return stats, err
	}
	if len(percentages) > 0 {
		stats.CpuUsage = percentages[0]
	}

	incomingSpeed, outgoingSpeed := getBandwidthSpeed()
	stats.IncomingBandwidthSpeed = incomingSpeed
	stats.OutgoingBandwidthSpeed = outgoingSpeed

	return stats, nil
}

func getBandwidthSpeed() (uint64, uint64) {
	counters, err := net.IOCounters(true)
	if err != nil {
		return 0, 0
	}

	now := time.Now()
	var totalRx, totalTx uint64
	for _, c := range counters {
		if c.Name == "lo" {
			continue
		}
		totalRx += c.BytesRecv
		totalTx += c.BytesSent
	}

	bwMu.Lock()
	defer bwMu.Unlock()

	if !bwInitialized {
		bwState = bandwidthState{
			lastRxBytes: totalRx,
			lastTxBytes: totalTx,
			lastTime:    now,
		}
		bwInitialized = true
		return 0, 0
	}

	elapsed := now.Sub(bwState.lastTime).Seconds()
	if elapsed <= 0 {
		return 0, 0
	}

	var rxSpeed, txSpeed uint64
	if totalRx >= bwState.lastRxBytes {
		rxSpeed = uint64(float64(totalRx-bwState.lastRxBytes) / elapsed)
	}
	if totalTx >= bwState.lastTxBytes {
		txSpeed = uint64(float64(totalTx-bwState.lastTxBytes) / elapsed)
	}

	bwState.lastRxBytes = totalRx
	bwState.lastTxBytes = totalTx
	bwState.lastTime = now

	return rxSpeed, txSpeed
}
