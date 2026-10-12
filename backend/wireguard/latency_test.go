package wireguard

import (
	"testing"

	"github.com/pasarguard/node/config"
)

func TestLatencyProbeInterfaceFallsBackToConfiguredInterface(t *testing.T) {
	wg := &WireGuard{
		cfg:    &config.Config{WGNATOutputInterface: ""},
		config: &Config{InterfaceName: "wg-test"},
	}

	if got := wg.latencyProbeInterface(); got != "wg-test" {
		t.Fatalf("unexpected interface: got %s want wg-test", got)
	}
}

func TestLatencyProbeInterfacePrefersNATEgressConfig(t *testing.T) {
	wg := &WireGuard{
		cfg:    &config.Config{WGNATOutputInterface: "eth9"},
		config: &Config{InterfaceName: "wg-test"},
	}

	if got := wg.latencyProbeInterface(); got != "eth9" {
		t.Fatalf("unexpected interface: got %s want eth9", got)
	}
}
