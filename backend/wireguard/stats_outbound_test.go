package wireguard

import (
	"context"
	"errors"
	"testing"

	"github.com/pasarguard/node/common"
	pkgstats "github.com/pasarguard/node/pkg/stats"
	"github.com/vishvananda/netlink"
)

type rxTxPair struct {
	rx uint64
	tx uint64
}

func managerWithInterfaceStatsSequence(t *testing.T, seq []rxTxPair) *Manager {
	t.Helper()
	callIndex := 0
	return &Manager{
		iFaceName: "wg-test",
		nl: mockNetlinkOps{
			linkByName: func(name string) (netlink.Link, error) {
				if len(seq) == 0 {
					return nil, errors.New("empty stats sequence")
				}

				current := seq[len(seq)-1]
				if callIndex < len(seq) {
					current = seq[callIndex]
				}
				callIndex++

				return &netlink.Dummy{
					LinkAttrs: netlink.LinkAttrs{
						Name: name,
						Statistics: &netlink.LinkStatistics{
							RxBytes: current.rx,
							TxBytes: current.tx,
						},
					},
				}, nil
			},
		},
	}
}

func statValueByType(t *testing.T, resp *common.StatResponse, typ string) int64 {
	t.Helper()
	for _, stat := range resp.GetStats() {
		if stat.GetType() == typ {
			return stat.GetValue()
		}
	}
	return 0
}

func TestGetStatsOutboundsUsesInterfaceDeltaAndLink(t *testing.T) {
	manager := managerWithInterfaceStatsSequence(t, []rxTxPair{
		{rx: 100, tx: 200}, // baseline
		{rx: 150, tx: 260}, // delta
	})

	wg := &WireGuard{
		config:         &Config{InterfaceName: "wg-test"},
		manager:        manager,
		state:          lifecycleRunning,
		interfaceStats: pkgstats.NewInterfaceCountersTracker(),
	}

	_, err := wg.GetStats(context.Background(), &common.StatRequest{
		Type:   common.StatType_Outbounds,
		Reset_: false,
	})
	if err != nil {
		t.Fatalf("failed to prime baseline: %v", err)
	}

	resp, err := wg.GetStats(context.Background(), &common.StatRequest{
		Type:   common.StatType_Outbounds,
		Reset_: false,
	})
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if got := statValueByType(t, resp, "downlink"); got != 50 {
		t.Fatalf("unexpected downlink delta: got %d want 50", got)
	}
	if got := statValueByType(t, resp, "uplink"); got != 60 {
		t.Fatalf("unexpected uplink delta: got %d want 60", got)
	}

	for _, stat := range resp.GetStats() {
		if stat.GetName() != "wg-test" {
			t.Fatalf("unexpected stat name: got %s want wg-test", stat.GetName())
		}
		if stat.GetLink() != "interface" {
			t.Fatalf("unexpected stat link: got %s want interface", stat.GetLink())
		}
	}
}

func TestGetStatsOutboundsResetBaseline(t *testing.T) {
	manager := managerWithInterfaceStatsSequence(t, []rxTxPair{
		{rx: 100, tx: 200}, // baseline
		{rx: 140, tx: 260}, // non-reset
		{rx: 160, tx: 300}, // reset call
		{rx: 170, tx: 310}, // post-reset
	})

	wg := &WireGuard{
		config:         &Config{InterfaceName: "wg-test"},
		manager:        manager,
		state:          lifecycleRunning,
		interfaceStats: pkgstats.NewInterfaceCountersTracker(),
	}

	_, err := wg.GetStats(context.Background(), &common.StatRequest{Type: common.StatType_Outbounds})
	if err != nil {
		t.Fatalf("failed to prime baseline: %v", err)
	}

	resp, err := wg.GetStats(context.Background(), &common.StatRequest{Type: common.StatType_Outbounds})
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if got := statValueByType(t, resp, "downlink"); got != 40 {
		t.Fatalf("unexpected downlink delta before reset: got %d want 40", got)
	}
	if got := statValueByType(t, resp, "uplink"); got != 60 {
		t.Fatalf("unexpected uplink delta before reset: got %d want 60", got)
	}

	resp, err = wg.GetStats(context.Background(), &common.StatRequest{
		Type:   common.StatType_Outbounds,
		Reset_: true,
	})
	if err != nil {
		t.Fatalf("GetStats reset failed: %v", err)
	}
	if got := statValueByType(t, resp, "downlink"); got != 60 {
		t.Fatalf("unexpected downlink delta on reset: got %d want 60", got)
	}
	if got := statValueByType(t, resp, "uplink"); got != 100 {
		t.Fatalf("unexpected uplink delta on reset: got %d want 100", got)
	}

	resp, err = wg.GetStats(context.Background(), &common.StatRequest{Type: common.StatType_Outbounds})
	if err != nil {
		t.Fatalf("GetStats post-reset failed: %v", err)
	}
	if got := statValueByType(t, resp, "downlink"); got != 10 {
		t.Fatalf("unexpected downlink delta after reset: got %d want 10", got)
	}
	if got := statValueByType(t, resp, "uplink"); got != 10 {
		t.Fatalf("unexpected uplink delta after reset: got %d want 10", got)
	}
}

func TestGetStatsOutboundsRebasesOnCounterRollback(t *testing.T) {
	manager := managerWithInterfaceStatsSequence(t, []rxTxPair{
		{rx: 200, tx: 300}, // baseline
		{rx: 150, tx: 250}, // rollback/restart
		{rx: 170, tx: 260}, // growth after rebase
	})

	wg := &WireGuard{
		config:         &Config{InterfaceName: "wg-test"},
		manager:        manager,
		state:          lifecycleRunning,
		interfaceStats: pkgstats.NewInterfaceCountersTracker(),
	}

	_, err := wg.GetStats(context.Background(), &common.StatRequest{Type: common.StatType_Outbounds})
	if err != nil {
		t.Fatalf("failed to prime baseline: %v", err)
	}

	resp, err := wg.GetStats(context.Background(), &common.StatRequest{Type: common.StatType_Outbounds})
	if err != nil {
		t.Fatalf("GetStats rollback failed: %v", err)
	}
	if len(resp.GetStats()) != 0 {
		t.Fatalf("expected zero stats immediately after rollback, got %d", len(resp.GetStats()))
	}

	resp, err = wg.GetStats(context.Background(), &common.StatRequest{Type: common.StatType_Outbounds})
	if err != nil {
		t.Fatalf("GetStats after rollback failed: %v", err)
	}
	if got := statValueByType(t, resp, "downlink"); got != 20 {
		t.Fatalf("unexpected downlink delta after rollback rebase: got %d want 20", got)
	}
	if got := statValueByType(t, resp, "uplink"); got != 10 {
		t.Fatalf("unexpected uplink delta after rollback rebase: got %d want 10", got)
	}
}

func TestGetStatsOutboundUsesRequestNameAndInterfaceLink(t *testing.T) {
	manager := managerWithInterfaceStatsSequence(t, []rxTxPair{
		{rx: 10, tx: 20}, // baseline
		{rx: 30, tx: 50}, // delta
	})

	wg := &WireGuard{
		config:         &Config{InterfaceName: "wg-test"},
		manager:        manager,
		state:          lifecycleRunning,
		interfaceStats: pkgstats.NewInterfaceCountersTracker(),
	}

	_, err := wg.GetStats(context.Background(), &common.StatRequest{
		Type: common.StatType_Outbound,
		Name: "custom-outbound",
	})
	if err != nil {
		t.Fatalf("failed to prime baseline: %v", err)
	}

	resp, err := wg.GetStats(context.Background(), &common.StatRequest{
		Type: common.StatType_Outbound,
		Name: "custom-outbound",
	})
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	for _, stat := range resp.GetStats() {
		if stat.GetName() != "custom-outbound" {
			t.Fatalf("unexpected stat name: got %s want custom-outbound", stat.GetName())
		}
		if stat.GetLink() != "interface" {
			t.Fatalf("unexpected stat link: got %s want interface", stat.GetLink())
		}
	}
}

func TestGetStatsOutboundsReturnsErrorWhenInterfaceStatsUnavailable(t *testing.T) {
	wg := &WireGuard{
		config: &Config{InterfaceName: "wg-test"},
		state:  lifecycleRunning,
		manager: &Manager{
			iFaceName: "wg-test",
			nl: mockNetlinkOps{
				linkByName: func(_ string) (netlink.Link, error) {
					return nil, errors.New("link unavailable")
				},
			},
		},
	}

	if _, err := wg.GetStats(context.Background(), &common.StatRequest{
		Type: common.StatType_Outbounds,
	}); err == nil {
		t.Fatal("expected error when interface stats are unavailable")
	}
}
