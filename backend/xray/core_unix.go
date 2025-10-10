//go:build !windows

package xray

import (
	"os/exec"
	"syscall"
)

// setProcAttributes sets Unix-specific process attributes for proper process management
func setProcAttributes(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}
}