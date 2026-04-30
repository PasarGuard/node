//go:build !linux

package wireguard

// applyLinuxHostRouting is a no-op on non-Linux platforms.
func applyLinuxHostRouting(_ string) func() { return nil }
