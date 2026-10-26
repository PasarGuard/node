//go:build linux

package mtproto

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

// defaultSIGHUP gives SIGHUP its default action, which ends the process, so
// the fake's SigCgt mask lacks SIGHUP until signal.Notify, like telemt's
// before its config watcher installs the handler; the Go runtime catches
// SIGHUP from the start otherwise. signal.Ignore makes the runtime let go of
// SIGHUP first, so a later signal.Notify installs its handler again.
func defaultSIGHUP() {
	signal.Ignore(syscall.SIGHUP)
	var action [4]uint64 // SIG_DFL, no flags, empty mask
	_, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGACTION, uintptr(syscall.SIGHUP), uintptr(unsafe.Pointer(&action)), 0, 8, 0, 0)
	if errno != 0 {
		fmt.Fprintln(os.Stderr, "fake telemt: failed to reset SIGHUP:", errno)
	}
}
