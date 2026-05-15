package wireguard

import "testing"

func TestLatencyProbeInterfaceFallsBackToConfiguredInterface(t *testing.T) {
	t.Setenv(wireGuardNATOutputInterfaceEnv, "")

	wg := &WireGuard{
		config: &Config{InterfaceName: "wg-test"},
	}

	if got := wg.latencyProbeInterface(); got != "wg-test" {
		t.Fatalf("unexpected interface: got %s want wg-test", got)
	}
}

func TestLatencyProbeInterfacePrefersNATEgressEnv(t *testing.T) {
	t.Setenv(wireGuardNATOutputInterfaceEnv, "eth9")

	wg := &WireGuard{
		config: &Config{InterfaceName: "wg-test"},
	}

	if got := wg.latencyProbeInterface(); got != "eth9" {
		t.Fatalf("unexpected interface: got %s want eth9", got)
	}
}
