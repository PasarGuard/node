package tools

import (
	"bufio"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"os"
	"strconv"
	"strings"
	"time"
)

type SystemStats struct {
	MemTotal               uint64  `json:"mem_total"`
	MemUsed                uint64  `json:"mem_used"`
	CpuCores               int     `json:"cpu_cores"`
	CpuUsage               float64 `json:"cpu_usage"`
	IncomingBandwidthSpeed int     `json:"incoming_bandwidth_speed"`
	OutgoingBandwidthSpeed int     `json:"outgoing_bandwidth_speed"`
}

func GetSystemStats() (SystemStats, error) {
	stats := SystemStats{}

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
	stats.CpuCores = cores

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

func getBandwidthSpeed() (int, int, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	var totalRxBytes, totalTxBytes uint64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ":") {
			fields := strings.Fields(line)
			if len(fields) < 17 {
				continue
			}

			rxBytes, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, 0, err
			}

			txBytes, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil {
				return 0, 0, err
			}

			totalRxBytes += rxBytes
			totalTxBytes += txBytes
		}
	}

	// Measure again after 1 second to calculate the speed
	time.Sleep(1 * time.Second)

	file.Seek(0, 0)
	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ":") {
			fields := strings.Fields(line)
			if len(fields) < 17 {
				continue
			}

			rxBytes, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, 0, err
			}

			txBytes, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil {
				return 0, 0, err
			}

			totalRxBytes = rxBytes - totalRxBytes
			totalTxBytes = txBytes - totalTxBytes
		}
	}

	return int(totalRxBytes), int(totalTxBytes), nil
}
