package stats

import (
	"context"
	"testing"
)

func TestBytesReceivedFromAWireGuardPeerAreReportedAsUplink(t *testing.T) {
	tracker := New()
	tracker.UpdateStatsBatch([]Sample{{PublicKey: "peer", Email: "user", Rx: 1000, Tx: 7}})

	got := map[string]int64{}
	for _, s := range tracker.GetUsersStats(context.Background(), false).GetStats() {
		got[s.Type] = s.Value
	}
	if got["uplink"] != 1000 || got["downlink"] != 7 {
		t.Fatalf("peer Rx=1000 (client upload) Tx=7 (client download) reported as uplink=%d downlink=%d", got["uplink"], got["downlink"])
	}
}

func TestInterfaceBytesReceivedAreReportedAsUplink(t *testing.T) {
	got := map[string]int64{}
	for _, s := range BuildInterfaceStats("wg0", "", 1000, 7) {
		got[s.Type] = s.Value
	}
	if got["uplink"] != 1000 || got["downlink"] != 7 {
		t.Fatalf("interface rx=1000 tx=7 reported as uplink=%d downlink=%d", got["uplink"], got["downlink"])
	}
}
