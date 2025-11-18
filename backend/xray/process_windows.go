//go:build windows

package xray

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

// findXrayProcesses finds all running xray processes by executable path
// Returns process information including PID, PPID, and zombie state
func findXrayProcesses(executablePath string) ([]ProcessInfo, error) {
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

		// Check if executable path matches
		if procPath == "" {
			continue
		}

		procAbsPath, err := filepath.Abs(procPath)
		if err != nil {
			continue
		}

		// Check if this is an xray process by executable path
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

		// Check if process is zombie (on Windows, check if process is still valid)
		isZombie := isProcessZombie(pid)

		processes = append(processes, ProcessInfo{
			PID:      pid,
			PPID:     ppid,
			IsZombie: isZombie,
		})
	}

	return processes, nil
}

// getProcessPath gets the full path of a process by PID on Windows
func getProcessPath(pid int) (string, error) {
	// Use wmic to get process executable path
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "ExecutablePath", "/format:list")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ExecutablePath=") {
			path := strings.TrimPrefix(line, "ExecutablePath=")
			return strings.TrimSpace(path), nil
		}
	}

	return "", fmt.Errorf("executable path not found for PID %d", pid)
}

// killProcessTree kills a process and all its children on Windows
func killProcessTree(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		// Process might not exist, check if it's running
		if !isProcessRunning(pid) {
			return nil
		}
		return fmt.Errorf("failed to find process %d: %w", pid, err)
	}

	// Try graceful termination first (CTRL_BREAK_EVENT for process groups)
	// For process groups created with CREATE_NEW_PROCESS_GROUP, we need to use
	// GenerateConsoleCtrlEvent to send signals to the group
	_ = proc.Signal(syscall.SIGTERM)

	// Use taskkill with /T flag to kill process tree (parent and all children)
	// /F forces termination, /T kills child processes, /PID specifies the process
	cmd := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid))
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if process is already dead (taskkill returns error if process not found)
		if !isProcessRunning(pid) {
			return nil
		}
		// Check if error is because process doesn't exist
		outputStr := strings.ToLower(string(output))
		if strings.Contains(outputStr, "not found") || strings.Contains(outputStr, "does not exist") {
			return nil
		}
		return fmt.Errorf("failed to kill process tree %d: %w (output: %s)", pid, err, string(output))
	}

	// Give it a moment to terminate
	// Verify it's actually dead
	if !isProcessRunning(pid) {
		return nil
	}

	// If still running, try one more time with more aggressive approach
	// This shouldn't normally happen, but just in case
	time.Sleep(100 * time.Millisecond)
	if !isProcessRunning(pid) {
		return nil
	}

	return fmt.Errorf("process %d is still running after kill attempt", pid)
}

// verifyProcessDead checks if a process is actually dead
func verifyProcessDead(pid int) error {
	if !isProcessRunning(pid) {
		return nil
	}
	return fmt.Errorf("process %d is still running", pid)
}

// isProcessRunning checks if a process is still running
func isProcessRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// Try to signal the process - if it fails, it's likely dead
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

// isProcessZombie checks if a process is a zombie on Windows
// On Windows, we check if the process exists but parent doesn't exist or is invalid
func isProcessZombie(pid int) bool {
	// Get process info to check parent
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ProcessId=%d", pid), "get", "ParentProcessId", "/format:list")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	var ppidStr string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ParentProcessId=") {
			ppidStr = strings.TrimPrefix(line, "ParentProcessId=")
			ppidStr = strings.TrimSpace(ppidStr)
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

	// Check if parent process exists
	// If parent doesn't exist but this process does, it might be orphaned
	// However, on Windows, orphaned processes are typically adopted by init (PID 0 or 4)
	// So we check if parent is system process and this process still exists
	if ppid <= 4 {
		// Parent is system process, check if this process is still running
		// but might be in a bad state
		return isProcessRunning(pid)
	}

	// Check if parent process exists
	parentExists := isProcessRunning(ppid)
	if !parentExists && isProcessRunning(pid) {
		// Process exists but parent doesn't - likely orphaned/zombie
		return true
	}

	return false
}

