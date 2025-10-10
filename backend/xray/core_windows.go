//go:build windows

package xray

import (
	"os/exec"
	"syscall"
)

// setProcAttributes sets Windows-specific process attributes for proper process management
func setProcAttributes(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}