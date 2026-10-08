//go:build linux

package udp2raw

import (
	"os/exec"
	"syscall"
)

// setPgid puts a namespace child in its own process group, so one kill takes
// the udp2raw processes it started with it.
func setPgid(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup kills a whole process group (negative pid). It never runs on a
// host without namespaces: the tests that spawn children skip there first.
func killGroup(pid int) { _ = syscall.Kill(-pid, syscall.SIGKILL) }
