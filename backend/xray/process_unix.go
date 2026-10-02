//go:build !windows

package xray

import "github.com/pasarguard/node/backend/proclib"

// Thin wrappers keeping the xray package's historical names; implementations
// live in backend/proclib so the sing-box backend shares them.

type ProcessInfo = proclib.ProcessInfo

func findXrayProcesses(executablePath string) ([]ProcessInfo, error) {
	return proclib.FindProcesses(executablePath)
}

func killProcessTree(pid int) error {
	return proclib.KillProcessTree(pid)
}

func verifyProcessDead(pid int) error {
	return proclib.VerifyProcessDead(pid)
}

func isProcessRunning(pid int) bool {
	return proclib.IsProcessRunning(pid)
}
