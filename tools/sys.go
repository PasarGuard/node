package tools

import (
	"bufio"
	"github.com/m03ed/marzban-node-go/common"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
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
	stats.IncomingBandwidthSpeed = uint64(incomingSpeed)
	stats.OutgoingBandwidthSpeed = uint64(outgoingSpeed)

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
