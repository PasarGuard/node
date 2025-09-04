package tools

import (
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/pasarguard/node/common"
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

	incomingSpeed, outgoingSpeed, err := getBandwidthSpeed()
	if err != nil {
		return stats, err
	}
	stats.IncomingBandwidthSpeed = incomingSpeed
	stats.OutgoingBandwidthSpeed = outgoingSpeed

	return stats, nil
}

// getBandwidthSpeed returns the aggregate incoming (rx) and outgoing (tx)
// bandwidth in bytes per second, sampled over a 1‑second interval.
func getBandwidthSpeed() (uint64, uint64, error) {
	// 1) First snapshot
	first, err := net.IOCounters(true)
	if err != nil {
		return 0, 0, err
	}

	// 2) Wait one second
	time.Sleep(1 * time.Second)

	// 3) Second snapshot
	second, err := net.IOCounters(true)
	if err != nil {
		return 0, 0, err
	}

	// 4) Compute deltas and sum across all interfaces
	//    Build a map from interface name → first snapshot
	prev := make(map[string]net.IOCountersStat, len(first))
	for _, c := range first {
		prev[c.Name] = c
	}

	var totalRx, totalTx uint64
	for _, c := range second {
		if p, ok := prev[c.Name]; ok {
			totalRx += c.BytesRecv - p.BytesRecv
			totalTx += c.BytesSent - p.BytesSent
		}
	}

	// 5) Return the totals
	return totalRx, totalTx, nil
}
