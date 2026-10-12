//go:build !linux

package wireguard

import "github.com/pasarguard/node/config"

// applyLinuxHostRouting is a no-op on non-Linux platforms.
func applyLinuxHostRouting(_ *config.Config, _ string) func() { return nil }
