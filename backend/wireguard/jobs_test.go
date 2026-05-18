package wireguard

import (
	"context"
	"testing"
	"time"

	"github.com/pasarguard/node/config"
	pkgstats "github.com/pasarguard/node/pkg/stats"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestUpdateConnectedPeersSkipsStaleHandshakePeers(t *testing.T) {
	_, recentPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate recent key pair: %v", err)
	}
	_, stalePub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate stale key pair: %v", err)
	}

	recentKey, err := wgtypes.ParseKey(recentPub)
	if err != nil {
		t.Fatalf("failed to parse recent public key: %v", err)
	}
	staleKey, err := wgtypes.ParseKey(stalePub)
	if err != nil {
		t.Fatalf("failed to parse stale public key: %v", err)
	}

	now := time.Now()
	manager := &Manager{
		iFaceName: "wg-test",
		client: &fakeWGClient{
			deviceFn: func(_ string) (*wgtypes.Device, error) {
				return &wgtypes.Device{Peers: []wgtypes.Peer{
					{
						PublicKey:         recentKey,
						LastHandshakeTime: now,
						ReceiveBytes:      120,
						TransmitBytes:     80,
					},
					{
						PublicKey:         staleKey,
						LastHandshakeTime: now.Add(-onlineActivityThreshold - time.Second),
						ReceiveBytes:      300,
						TransmitBytes:     200,
					},
				}}, nil
			},
		},
	}

	peerStore := NewPeerStore()
	peerStore.Init([]*PeerInfo{
		{Email: "recent@example.com", PublicKey: recentKey},
		{Email: "stale@example.com", PublicKey: staleKey},
	})

	wg := &WireGuard{
		manager:      manager,
		cfg:          &config.Config{},
		config:       &Config{},
		peerStore:    peerStore,
		statsTracker: pkgstats.New(),
	}

	emailByKey := wg.peerStore.GetEmailMap()
	if got := emailByKey[recentKey.String()]; got != "recent@example.com" {
		t.Fatalf("unexpected recent peer mapping: got %q", got)
	}
	if got := emailByKey[staleKey.String()]; got != "stale@example.com" {
		t.Fatalf("unexpected stale peer mapping: got %q", got)
	}

	wg.updateConnectedPeers(context.Background())

	entries := wg.statsTracker.GetStatsEntries([]string{recentKey.String(), staleKey.String()})
	if len(entries) != 1 {
		t.Fatalf("expected one tracked peer entry, got %d", len(entries))
	}
	if _, ok := entries[recentKey.String()]; !ok {
		t.Fatalf("expected recent peer to be tracked, but it was not")
	}
	if _, ok := entries[staleKey.String()]; ok {
		t.Fatalf("expected stale peer to be excluded from tracking")
	}

	resp := wg.statsTracker.GetUsersStats(context.Background(), false)

	if len(resp.GetStats()) != 2 {
		t.Fatalf("expected stats only for one active peer (2 entries), got %d", len(resp.GetStats()))
	}

	for _, stat := range resp.GetStats() {
		if stat.GetName() != "recent@example.com" {
			t.Fatalf("unexpected user in stats: got %s, expected only recent@example.com", stat.GetName())
		}
	}
}
