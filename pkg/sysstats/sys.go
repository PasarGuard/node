package sysstats

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"

	"github.com/pasarguard/node/common"
)

const sampleInterval = time.Second

var (
	cpuCoresOnce sync.Once
	cpuCores     uint64
	cpuCoresErr  error
)

func cachedCPUCores() (uint64, error) {
	cpuCoresOnce.Do(func() {
		n, err := cpu.Counts(true)
		if err != nil {
			cpuCoresErr = err
			return
		}
		cpuCores = uint64(n)
	})
	return cpuCores, cpuCoresErr
}

func GetSystemStats(ctx context.Context) (*common.SystemStatsResponse, error) {
	stats := &common.SystemStatsResponse{}
	if err := ctx.Err(); err != nil {
		return stats, err
	}

	vm, err := mem.VirtualMemory()
	if err != nil {
		return stats, err
	}
	stats.MemTotal = vm.Total
	stats.MemUsed = vm.Used

	cores, err := cachedCPUCores()
	if err != nil {
		return stats, err
	}
	stats.CpuCores = cores

	cpuFirst, err := cpu.Times(false)
	if err != nil {
		return stats, err
	}
	netFirst, err := net.IOCounters(true)
	if err != nil {
		return stats, err
	}

	if err := waitSample(ctx, sampleInterval); err != nil {
		return stats, err
	}

	cpuSecond, err := cpu.Times(false)
	if err != nil {
		return stats, err
	}
	netSecond, err := net.IOCounters(true)
	if err != nil {
		return stats, err
	}

	if len(cpuFirst) > 0 && len(cpuSecond) > 0 {
		stats.CpuUsage = cpuPercent(cpuFirst[0], cpuSecond[0])
	}
	stats.IncomingBandwidthSpeed, stats.OutgoingBandwidthSpeed = bandwidthDelta(netFirst, netSecond)

	return stats, nil
}

func waitSample(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func cpuPercent(t1, t2 cpu.TimesStat) float64 {
	t1All, t1Busy := cpuBusyTotal(t1)
	t2All, t2Busy := cpuBusyTotal(t2)

	if t2Busy <= t1Busy {
		return 0
	}
	if t2All <= t1All {
		return 100
	}
	return math.Min(100, math.Max(0, (t2Busy-t1Busy)/(t2All-t1All)*100))
}

func cpuBusyTotal(t cpu.TimesStat) (all, busy float64) {
	busy = t.User + t.System + t.Nice + t.Iowait + t.Irq + t.Softirq + t.Steal
	return busy + t.Idle, busy
}

// bandwidthDelta returns aggregate incoming (rx) and outgoing (tx) bytes
// between two IO counter snapshots. Loopback (lo) is excluded.
func bandwidthDelta(first, second []net.IOCountersStat) (uint64, uint64) {
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

	return totalRxBytes, totalTxBytes
}
