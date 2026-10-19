//go:build !linux && !windows

package mtproto

// defaultSIGHUP does nothing here: the Go runtime already ends the fake on a
// SIGHUP before signal.Notify, and outside Linux the node cannot read signal
// handlers, so it waits telemtSignalGrace instead.
func defaultSIGHUP() {}
