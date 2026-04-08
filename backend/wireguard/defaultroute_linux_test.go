//go:build linux

package wireguard

import "testing"

func TestParseDefaultIfaceFromProcNetRoute(t *testing.T) {
	const sample = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"ens33\t00000000\t010AA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"

	got, ok := parseDefaultIfaceFromProcNetRoute([]byte(sample))
	if !ok || got != "ens33" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}
