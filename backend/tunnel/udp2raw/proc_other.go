//go:build !linux

package udp2raw

import (
	"os"
	"os/exec"
)

// setPgid is a no-op off Linux: the tests that need it skip before spawning
// anything (they require network namespaces, which only Linux creates).
func setPgid(cmd *exec.Cmd) {}

// killGroup falls back to killing the single process. Nothing in a skipped
// test has spawned a child by then.
func killGroup(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}
