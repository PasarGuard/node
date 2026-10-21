package wireguard

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/stats"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// counterKernel models the kernel peer table with its traffic counters: a peer created by a
// config starts at zero, ReplacePeers re-creates every peer and Remove drops one.
type counterKernel struct {
	mu    sync.Mutex
	peers map[wgtypes.Key]*wgtypes.Peer
}

func newCounterKernel() *counterKernel {
	return &counterKernel{peers: make(map[wgtypes.Key]*wgtypes.Peer)}
}

func (k *counterKernel) ConfigureDevice(_ string, cfg wgtypes.Config) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if cfg.ReplacePeers {
		k.peers = make(map[wgtypes.Key]*wgtypes.Peer)
	}
	for _, peer := range cfg.Peers {
		if peer.Remove {
			delete(k.peers, peer.PublicKey)
			continue
		}
		if _, exists := k.peers[peer.PublicKey]; !exists {
			k.peers[peer.PublicKey] = &wgtypes.Peer{PublicKey: peer.PublicKey}
		}
	}
	return nil
}

func (k *counterKernel) Device(string) (*wgtypes.Device, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	device := &wgtypes.Device{}
	for _, peer := range k.peers {
		device.Peers = append(device.Peers, *peer)
	}
	return device, nil
}

func (k *counterKernel) Close() error { return nil }

// move counts n bytes in each direction on a live peer, as a connected client would.
func (k *counterKernel) move(t *testing.T, publicKey string, n int64) {
	t.Helper()
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	peer, exists := k.peers[key]
	if !exists {
		t.Fatalf("peer %s is not in the kernel", publicKey)
	}
	peer.ReceiveBytes += n
	peer.TransmitBytes += n
	peer.LastHandshakeTime = time.Now()
}

// ageHandshake moves a peer's last handshake into the past, as between WireGuard rekeys.
func (k *counterKernel) ageHandshake(t *testing.T, publicKey string, age time.Duration) {
	t.Helper()
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	peer, exists := k.peers[key]
	if !exists {
		t.Fatalf("peer %s is not in the kernel", publicKey)
	}
	peer.LastHandshakeTime = time.Now().Add(-age)
}

func newCounterTestWG(t *testing.T, client wgClient) *WireGuard {
	t.Helper()
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	cfg, err := NewConfig(fmt.Sprintf(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.74.0.1/24"],
		"private_key":"%s"
	}`, privateKey))
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	return &WireGuard{
		config:       cfg,
		peerStore:    NewPeerStore(),
		statsTracker: stats.New(),
		manager:      &Manager{iFaceName: "wg-test", client: client},
		state:        lifecycleRunning,
	}
}

func counterTestUser(email, publicKey, peerIP string) *common.User {
	user := &common.User{
		Email:   email,
		Proxies: &common.Proxy{Wireguard: &common.Wireguard{PublicKey: publicKey}},
	}
	if peerIP != "" {
		user.Inbounds = []string{"wg-test"}
		user.Proxies.Wireguard.PeerIps = []string{peerIP}
	}
	return user
}

// Every way the node re-creates a kernel peer (full sync ReplacePeers, Restart, remove then
// re-add before or after a stats pull) restarts its counters at zero. The traffic counted on
// both sides of each reset must reach the panel exactly once, including a new counter that
// already passed the old one when it is first sampled, and traffic moved since the last stats
// tick right before a ReplacePeers.
func TestPeerCounterResetsReportEachByteOnce(t *testing.T) {
	ctx := context.Background()
	kernel := newCounterKernel()
	wg := newCounterTestWG(t, kernel)

	keys := make([]string, 3)
	for i := range keys {
		_, publicKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}
		keys[i] = publicKey
	}
	keep := counterTestUser("1", keys[0], "10.74.0.2/32")
	other := counterTestUser("2", keys[1], "10.74.0.3/32")
	otherWithoutAccess := counterTestUser("2", keys[1], "")
	third := counterTestUser("3", keys[2], "10.74.0.4/32")

	var moved, reportedRx, reportedTx int64
	move := func(publicKey string, n int64) {
		kernel.move(t, publicKey, n)
		moved += n
	}
	sample := func() { wg.updateConnectedPeers(ctx) }
	pull := func() {
		resp, err := wg.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
		if err != nil {
			t.Fatalf("GetStats failed: %v", err)
		}
		for _, stat := range resp.GetStats() {
			switch stat.GetType() {
			case "downlink":
				reportedRx += stat.GetValue()
			case "uplink":
				reportedTx += stat.GetValue()
			}
		}
	}
	mustSync := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("sync failed: %v", err)
		}
	}

	mustSync(wg.SyncUsers(ctx, []*common.User{keep, other}))
	move(keys[0], 1000)
	sample()
	pull()

	// Full sync with a change: ReplacePeers re-creates every peer. The new counter passes
	// the old one (1500) before the next sample.
	move(keys[0], 500)
	sample()
	// Traffic since the last tick, on a recently active peer and on one whose last handshake is
	// past the 45 s online cutoff (WireGuard rekeys only every ~2 minutes). The sync samples both
	// right before ReplacePeers destroys their counters.
	move(keys[0], 25)
	move(keys[1], 60)
	kernel.ageHandshake(t, keys[1], time.Minute)
	mustSync(wg.SyncUsers(ctx, []*common.User{keep, other, third}))
	move(keys[0], 5000)
	sample()
	pull()

	// Restart also re-applies the whole peer set with ReplacePeers.
	move(keys[0], 100)
	sample()
	move(keys[0], 15) // since the last tick
	mustSync(wg.Restart())
	move(keys[0], 50)
	sample()

	// Removed and re-added before the panel pulled the pending delta.
	move(keys[1], 300)
	sample()
	mustSync(wg.UpdateUsers(ctx, []*common.User{otherWithoutAccess}))
	mustSync(wg.UpdateUsers(ctx, []*common.User{other}))
	move(keys[1], 40)
	sample()
	pull()

	// Removed, everything reported, then re-added.
	mustSync(wg.UpdateUsers(ctx, []*common.User{otherWithoutAccess}))
	pull()
	mustSync(wg.UpdateUsers(ctx, []*common.User{other}))
	move(keys[1], 7)
	sample()
	pull()

	if reportedRx != moved || reportedTx != moved {
		t.Fatalf("reported rx %d / tx %d bytes, peers moved %d", reportedRx, reportedTx, moved)
	}
}

// A sample read from the device before a ReplacePeers and applied after the reset mark would
// count the old counter a second time, so sampling must wait for a running peer sync.
func TestUpdateConnectedPeersWaitsForRunningSync(t *testing.T) {
	wg := newCounterTestWG(t, newCounterKernel())

	deviceRead := make(chan struct{}, 1)
	wg.manager.client = &fakeWGClient{
		deviceFn: func(string) (*wgtypes.Device, error) {
			deviceRead <- struct{}{}
			return &wgtypes.Device{}, nil
		},
	}

	wg.syncMu.Lock()
	done := make(chan struct{})
	go func() {
		wg.updateConnectedPeers(context.Background())
		close(done)
	}()

	select {
	case <-deviceRead:
		wg.syncMu.Unlock()
		t.Fatal("stats sampling read the device while a peer sync held syncMu")
	case <-time.After(100 * time.Millisecond):
	}

	wg.syncMu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stats sampling did not finish after the sync released syncMu")
	}
}
