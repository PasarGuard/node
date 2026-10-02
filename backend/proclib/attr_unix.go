//go:build !windows

package proclib

import (
	"os/exec"
	"syscall"
)

// SetProcAttributes sets Unix-specific process attributes for proper process management
func SetProcAttributes(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}
}
