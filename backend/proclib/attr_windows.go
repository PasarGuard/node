//go:build windows

package proclib

import (
	"os/exec"
	"syscall"
)

// SetProcAttributes sets Windows-specific process attributes for proper process management.
// CREATE_NEW_PROCESS_GROUP allows sending signals to the process group; killProcessTree
// handles child processes.
func SetProcAttributes(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags:    syscall.CREATE_NEW_PROCESS_GROUP,
		NoInheritHandles: false,
	}
}
