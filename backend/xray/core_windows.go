//go:build windows

package xray

import (
	"os/exec"
	"syscall"
)

// setProcAttributes sets Windows-specific process attributes for proper process management
// We use CREATE_NEW_PROCESS_GROUP to allow sending signals to the process group,
// but we ensure proper cleanup in killProcessTree to handle child processes
func setProcAttributes(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		// NoInheritHandles ensures child processes don't inherit handles unnecessarily
		NoInheritHandles: false,
	}
}