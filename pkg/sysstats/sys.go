package sysstats

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
// bandwidth in bytes per second, sampled over a 1-second interval.
// Loopback interface (lo) is excluded from the calculation.
func getBandwidthSpeed() (uint64, uint64, error) {
	first, err := net.IOCounters(true)
	if err != nil {
		return 0, 0, err
	}

	time.Sleep(1 * time.Second)

	second, err := net.IOCounters(true)
	if err != nil {
		return 0, 0, err
	}

	prev := make(map[string]net.IOCountersStat, len(first))
	for _, c := range first {
		if c.Name == "lo" {
			continue
		}
		prev[c.Name] = c
	}

	var totalRxBytes, totalTxBytes uint64
	for _, c := range second {
		if c.Name == "lo" {
			continue
		}
		if p, ok := prev[c.Name]; ok {
			totalRxBytes += c.BytesRecv - p.BytesRecv
			totalTxBytes += c.BytesSent - p.BytesSent
		}
	}

	return totalRxBytes, totalTxBytes, nil
}
