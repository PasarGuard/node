//go:build windows

package proclib

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// FindProcesses finds all running processes matching the given executable path.
// Returns process information including PID, PPID, and zombie state.
func FindProcesses(executablePath string) ([]ProcessInfo, error) {
	absPath, err := filepath.Abs(executablePath)
	if err != nil {
		return nil, err
	}

	// Use wmic to get process info including parent PID
	cmd := exec.Command("wmic", "process", "get", "ProcessId,ParentProcessId,ExecutablePath", "/format:csv")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list processes: %w", err)
	}

	var processes []ProcessInfo
	lines := strings.Split(string(output), "\n")
	executableName := filepath.Base(absPath)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node") || strings.HasPrefix(line, "ProcessId") {
			continue
		}

		// CSV format: Node,ProcessId,ParentProcessId,ExecutablePath
		parts := strings.Split(line, ",")
		if len(parts) < 4 {
			continue
		}

		pidStr := strings.TrimSpace(parts[1])
		ppidStr := strings.TrimSpace(parts[2])
		procPath := strings.TrimSpace(parts[3])

		if procPath == "" {
			continue
		}

		procAbsPath, err := filepath.Abs(procPath)
		if err != nil {
			continue
		}

		if !strings.EqualFold(procAbsPath, absPath) {
			// Also check by name if path doesn't match (in case of symlinks)
			if !strings.EqualFold(filepath.Base(procAbsPath), executableName) {
				continue
			}
		}

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		ppid := 0
		if ppidStr != "" {
			ppid, err = strconv.Atoi(ppidStr)
			if err != nil {
				continue
			}
		}

		isZombie := IsProcessZombie(pid)

		processes = append(processes, ProcessInfo{
			PID:      pid,
			PPID:     ppid,
			IsZombie: isZombie,
		})
	}

	return processes, nil
}

// GetProcessPath gets the full path of a process by PID on Windows
func GetProcessPath(pid int) (string, error) {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "ExecutablePath", "/format:list")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.SplitSeq(string(output), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "ExecutablePath="); ok {
			return strings.TrimSpace(after), nil
		}
	}

	return "", fmt.Errorf("executable path not found for PID %d", pid)
}

// KillProcessTree kills a process and all its children on Windows
func KillProcessTree(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		if !IsProcessRunning(pid) {
			return nil
		}
		return fmt.Errorf("failed to find process %d: %w", pid, err)
	}

	_ = proc.Signal(syscall.SIGTERM)

	// Use taskkill with /T flag to kill process tree (parent and all children)
	cmd := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid))
	output, err := cmd.CombinedOutput()
	if err != nil {
		if !IsProcessRunning(pid) {
			return nil
		}
		outputStr := strings.ToLower(string(output))
		if strings.Contains(outputStr, "not found") || strings.Contains(outputStr, "does not exist") {
			return nil
		}
		return fmt.Errorf("failed to kill process tree %d: %w (output: %s)", pid, err, string(output))
	}

	if !IsProcessRunning(pid) {
		return nil
	}

	time.Sleep(100 * time.Millisecond)
	if !IsProcessRunning(pid) {
		return nil
	}

	return fmt.Errorf("process %d is still running after kill attempt", pid)
}

// VerifyProcessDead checks if a process is actually dead
func VerifyProcessDead(pid int) error {
	if !IsProcessRunning(pid) {
		return nil
	}
	return fmt.Errorf("process %d is still running", pid)
}

// IsProcessRunning checks if a process is still running
func IsProcessRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

// IsProcessZombie checks if a process is a zombie on Windows.
// On Windows, we check if the process exists but parent doesn't exist or is invalid.
func IsProcessZombie(pid int) bool {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "ParentProcessId", "/format:list")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	var ppidStr string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "ParentProcessId="); ok {
			ppidStr = strings.TrimSpace(after)
			break
		}
	}

	if ppidStr == "" {
		return false
	}

	ppid, err := strconv.Atoi(ppidStr)
	if err != nil {
		return false
	}

	// Parent is system process: treat the process as zombie only if still running
	if ppid <= 4 {
		return IsProcessRunning(pid)
	}

	// Process exists but parent doesn't - likely orphaned/zombie
	if !IsProcessRunning(ppid) && IsProcessRunning(pid) {
		return true
	}

	return false
}
