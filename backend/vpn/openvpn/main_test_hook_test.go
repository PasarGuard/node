package openvpn

import (
	"os"
	"testing"
)

// TestMain doubles as the hanging-auth helper: with PG_OVPN_HANG set the
// re-exec'd test binary never returns, which is the behaviour the bounded
// timeout test needs to prove it survives.
func TestMain(m *testing.M) {
	if os.Getenv("PG_OVPN_HANG") == "1" {
		select {}
	}
	os.Exit(m.Run())
}
