package wireguard

import (
	"context"
	"testing"

	pkgstats "github.com/pasarguard/node/pkg/stats"
)

func wireGuardWithPeersAndActivity(t *testing.T, peers []*PeerInfo, samples []pkgstats.Sample) *WireGuard {
	t.Helper()

	tracker := pkgstats.New()
	tracker.UpdateStatsBatch(samples)

	return &WireGuard{
		config:       &Config{InterfaceName: "wg-test"},
		state:        lifecycleRunning,
		peerStore:    mustPeerStoreWithPeers(t, peers...),
		statsTracker: tracker,
	}
}

func TestGetUsersOnlineIpListStatsReturnsOnlyActivePeers(t *testing.T) {
	peers := []*PeerInfo{
		mustPeerInfo("active@example.com", "activekey", []string{"10.0.0.2/32"}),
		mustPeerInfo("idle@example.com", "idlekey", []string{"10.0.0.3/32"}),
	}
	samples := []pkgstats.Sample{
		{
			PublicKey:  dummyKey("activekey").String(),
			Email:      "active@example.com",
			Rx:         100,
			Tx:         200,
			EndpointIP: "203.0.113.5",
		},
	}

	wg := wireGuardWithPeersAndActivity(t, peers, samples)

	resp, err := wg.GetUsersOnlineIpListStats(context.Background())
	if err != nil {
		t.Fatalf("GetUsersOnlineIpListStats failed: %v", err)
	}

	users := resp.GetUsers()
	if len(users) != 1 {
		t.Fatalf("expected exactly one online user, got %d (%v)", len(users), users)
	}

	active, ok := users["active@example.com"]
	if !ok {
		t.Fatalf("expected active@example.com in response, got %v", users)
	}
	if ts, ok := active.GetIps()["203.0.113.5"]; !ok || ts == 0 {
		t.Fatalf("expected non-zero last-seen for 203.0.113.5, got %v", active.GetIps())
	}

	if _, ok := users["idle@example.com"]; ok {
		t.Fatalf("did not expect idle@example.com in response, got %v", users)
	}
}

func TestGetUsersOnlineIpListStatsReturnsEmptyWhenNoActivity(t *testing.T) {
	peers := []*PeerInfo{
		mustPeerInfo("idle@example.com", "idlekey", []string{"10.0.0.3/32"}),
	}

	wg := wireGuardWithPeersAndActivity(t, peers, nil)

	resp, err := wg.GetUsersOnlineIpListStats(context.Background())
	if err != nil {
		t.Fatalf("GetUsersOnlineIpListStats failed: %v", err)
	}

	if len(resp.GetUsers()) != 0 {
		t.Fatalf("expected no online users, got %v", resp.GetUsers())
	}
}

func TestGetUsersOnlineIpListStatsErrorsWhenNotStarted(t *testing.T) {
	wg := &WireGuard{
		config:       &Config{InterfaceName: "wg-test"},
		state:        lifecycleStopped,
		peerStore:    NewPeerStore(),
		statsTracker: pkgstats.New(),
	}

	if _, err := wg.GetUsersOnlineIpListStats(context.Background()); err == nil {
		t.Fatal("expected error when wireguard backend is not running")
	}
}
