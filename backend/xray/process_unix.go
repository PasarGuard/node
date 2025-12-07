//go:build !windows

package xray

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

	// Prefer /proc on Linux (works on Alpine/busybox) to avoid relying on ps flags
	if runtime.GOOS == "linux" {
		if procs, perr := findXrayProcessesFromProc(absPath); perr == nil {
			// /proc is authoritative; even if empty, that's a valid result
			return procs, nil
		}
	}

	// Use ps to find processes with PID, PPID, state, and command
	cmd := exec.Command("ps", "-eo", "pid,ppid,state,command")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list processes: %w", err)
	}

	var processes []ProcessInfo
	lines := strings.Split(string(output), "\n")
	executableName := filepath.Base(absPath)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "PID") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		pidStr := fields[0]
		ppidStr := fields[1]
		state := fields[2]

		cmdPath := fields[3]

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		ppid, err := strconv.Atoi(ppidStr)
		if err != nil {
			continue
		}

		// Verify it's actually the same executable by checking full path when possible
		match := false
		if procPath, err := getProcessPath(pid); err == nil {
			match = pathsMatch(procPath, absPath)
		}

		// Fallback: compare first token of the command/args
		if !match {
			match = pathsMatch(cmdPath, absPath) || filepath.Base(cmdPath) == executableName
		}

		if !match {
			continue
		}

		// Check if process is zombie (state 'Z' in ps output)
		isZombie := state == "Z" || state == "z"

		processes = append(processes, ProcessInfo{
			PID:      pid,
			PPID:     ppid,
			IsZombie: isZombie,
		})
	}

	return processes, nil
}

// findXrayProcessesFromProc scans /proc directly (Linux-only)
func findXrayProcessesFromProc(absPath string) ([]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var processes []ProcessInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		// Check executable path
		exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			continue
		}
		if !pathsMatch(exePath, absPath) {
			continue
		}

		statPath := fmt.Sprintf("/proc/%d/stat", pid)
		data, err := os.ReadFile(statPath)
		if err != nil {
			continue
		}
		fields := strings.Fields(string(data))
		if len(fields) < 4 {
			continue
		}
		state := fields[2]
		ppid, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}

		processes = append(processes, ProcessInfo{
			PID:      pid,
			PPID:     ppid,
			IsZombie: state == "Z" || state == "z",
		})
	}

	return processes, nil
}

// getProcessPath gets the full path of a process by PID on Unix
func getProcessPath(pid int) (string, error) {
	// Read from /proc/PID/exe symlink
	procPath := fmt.Sprintf("/proc/%d/exe", pid)
	path, err := os.Readlink(procPath)
	if err == nil {
		return path, nil
	}

	// Fallback for systems without /proc (e.g., macOS)
	psOutput, psErr := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if psErr != nil {
		return "", fmt.Errorf("failed to read process path: %w (ps fallback error: %v)", err, psErr)
	}

	cmdline := strings.TrimSpace(string(psOutput))
	if cmdline == "" {
		return "", fmt.Errorf("failed to read process path: empty command for pid %d", pid)
	}

	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return "", fmt.Errorf("failed to read process path: empty command for pid %d", pid)
	}

	return fields[0], nil
}

// killProcessTree kills a process and all its children on Unix
func killProcessTree(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process %d: %w", pid, err)
	}

	// Try graceful termination first (SIGTERM)
	err = proc.Signal(syscall.SIGTERM)
	if err != nil {
		// Process might already be dead
	}

	// Wait a bit for graceful shutdown
	// Note: We can't easily wait here without blocking, so we'll just try SIGKILL after

	// Get process group ID and kill the whole group
	// First, try to get the pgid
	pgid, err := getProcessGroupID(pid)
	if err == nil && pgid != 0 {
		// Kill the entire process group
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
		// Give it a moment
		// Then force kill
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}

	// Also kill the specific process
	_ = proc.Signal(syscall.SIGKILL)

	// Wait briefly for the process to exit
	for i := 0; i < 10; i++ {
		if !isProcessRunning(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("process %d is still running after kill attempt", pid)
}

// getProcessGroupID gets the process group ID for a process
func getProcessGroupID(pid int) (int, error) {
	// Read from /proc/PID/stat
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0, err
	}

	// Parse stat file - format: pid comm state ppid pgrp ...
	fields := strings.Fields(string(data))
	if len(fields) < 5 {
		return 0, fmt.Errorf("invalid stat format")
	}

	pgid, err := strconv.Atoi(fields[4])
	if err != nil {
		return 0, err
	}

	return pgid, nil
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

// isProcessZombie checks if a process is a zombie on Unix
// This is already handled in findXrayProcesses by checking the state field
// But we provide this function for consistency
func isProcessZombie(pid int) bool {
	// Read from /proc/PID/stat to get process state
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		// Fallback to ps for systems without /proc
		out, psErr := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "state=").Output()
		if psErr != nil {
			return false
		}
		state := strings.TrimSpace(string(out))
		if state == "" {
			return false
		}
		return strings.HasPrefix(state, "Z") || strings.HasPrefix(state, "z")
	}

	// Parse stat file - format: pid comm state ppid ...
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return false
	}

	// State is the 3rd field (index 2)
	// 'Z' means zombie process
	state := fields[2]
	return state == "Z" || state == "z"
}

// pathsMatch compares two executable paths, resolving symlinks and absolutizing both
func pathsMatch(candidate, target string) bool {
	if candidate == "" || target == "" {
		return false
	}

	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}

	if candidateAbs == targetAbs {
		return true
	}

	candidateReal, errA := filepath.EvalSymlinks(candidateAbs)
	targetReal, errB := filepath.EvalSymlinks(targetAbs)
	if errA == nil && errB == nil && candidateReal == targetReal {
		return true
	}

	return false
}
