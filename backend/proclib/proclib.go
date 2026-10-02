// Package proclib provides cross-core process helpers shared by the xray and
// sing-box backends: executable discovery, tree kill, and liveness checks.
package proclib

// ProcessInfo holds information about a process.
type ProcessInfo struct {
	PID      int
	PPID     int
	IsZombie bool
}
