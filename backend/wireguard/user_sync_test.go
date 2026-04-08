package wireguard

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/stats"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestSyncUserRejectsNilUser(t *testing.T) {
	wg := &WireGuard{state: lifecycleRunning}

	err := wg.SyncUser(context.Background(), nil)
	if err == nil {
		t.Fatal("expected SyncUser to fail for nil user")
	}
	if !strings.Contains(err.Error(), "user is nil") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSyncUserRejectsUnparsableStoredPeer(t *testing.T) {
	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.61.0.1/24"]
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	invalidKey := "not-a-valid-wireguard-key"
	ps := NewPeerStore()
	ps.ReplaceAll([]*PeerInfo{mustPeerInfo("user@example.com", invalidKey, []string{"10.61.0.2/32"})})

	_, validKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	configureCalls := 0
	wg := &WireGuard{
		config:       cfg,
		peerStore:    ps,
		statsTracker: stats.New(),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				configureDeviceFn: func(interfaceName string, cfg wgtypes.Config) error {
					configureCalls++
					if interfaceName != "wg-test" {
						t.Fatalf("unexpected interface name: %s", interfaceName)
					}
					return nil
				},
			},
		},
		state: lifecycleRunning,
	}

	user := &common.User{
		Email:    "user@example.com",
		Inbounds: []string{"wg-test"},
		Proxies: &common.Proxy{
			Wireguard: &common.Wireguard{
				PublicKey: validKey, PeerIps: []string{"10.61.0.10/32"},
			},
		},
	}

	err = wg.SyncUser(context.Background(), user)
	if err != nil {
		t.Fatalf("expected SyncUser to succeed despite unparsable stored peer key, got: %v", err)
	}

	if configureCalls != 1 {
		t.Fatal("expected exactly one ConfigureDevice call syncing the valid new peer")
	}

	if peer := wg.peerStore.GetByKey(invalidKey); peer != nil {
		t.Fatal("expected invalid stored peer to be removed (quarantined) during sync")
	}

	if peer := wg.peerStore.GetByKey(validKey); peer == nil {
		t.Fatal("expected valid peer to be added successfully")
	}
}

func TestSyncUsersFailsWholeRequestOnInvalidKey(t *testing.T) {
	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.62.0.1/24"]
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, validKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	configureCalls := 0
	wg := &WireGuard{
		config:       cfg,
		peerStore:    NewPeerStore(),
		statsTracker: stats.New(),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				configureDeviceFn: func(interfaceName string, cfg wgtypes.Config) error {
					configureCalls++
					return nil
				},
			},
		},
		state: lifecycleRunning,
	}

	users := []*common.User{
		{
			Email:    "valid@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: validKey, PeerIps: []string{"10.62.0.2/32"},
				},
			},
		},
		{
			Email:    "invalid@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: "not-a-valid-wireguard-key", PeerIps: []string{"10.62.0.3/32"},
				},
			},
		},
	}

	err = wg.SyncUsers(context.Background(), users)
	if err != nil {
		t.Fatalf("expected SyncUsers to succeed (quarantining invalid key), got: %v", err)
	}

	if configureCalls != 1 {
		t.Fatal("expected one ConfigureDevice call when invalid key is skipped")
	}

	if peer := wg.peerStore.GetByKey(validKey); peer == nil {
		t.Fatal("expected valid peer to be added successfully")
	}
}

func TestSyncUsersSkipsEmptyEmailUser(t *testing.T) {
	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.62.0.1/24"]
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, validKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	configureCalls := 0
	wg := &WireGuard{
		config:       cfg,
		peerStore:    NewPeerStore(),
		statsTracker: stats.New(),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				configureDeviceFn: func(interfaceName string, cfg wgtypes.Config) error {
					configureCalls++
					return nil
				},
			},
		},
		state: lifecycleRunning,
	}

	users := []*common.User{
		{
			Email:    "",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: validKey, PeerIps: []string{"10.62.0.4/32"},
				},
			},
		},
	}

	// normalizeUsers drops users with empty email before they reach any sync logic.
	if err = wg.SyncUsers(context.Background(), users); err != nil {
		t.Fatalf("expected SyncUsers to succeed when normalizeUsers drops empty-email user, got: %v", err)
	}
	// No effective desired peers → no kernel call.
	if configureCalls != 0 {
		t.Fatalf("expected no ConfigureDevice call when the only user was quarantined, got %d", configureCalls)
	}
	// Nothing should have been added to the store.
	if peer := wg.peerStore.GetByKey(validKey); peer != nil {
		t.Fatal("expected quarantined user not to appear in the peer store")
	}
}

func TestSyncUsersReplaceAllRemovesStalePeersAndStats(t *testing.T) {
	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.63.0.1/24"]
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, keepKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate keep key: %v", err)
	}
	_, removeKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate remove key: %v", err)
	}
	_, newKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate new key: %v", err)
	}

	ps := NewPeerStore()
	ps.ReplaceAll([]*PeerInfo{mustPeerInfo("keep@example.com", keepKey, []string{"10.63.0.2/32"})})
	ps.ReplaceAll([]*PeerInfo{mustPeerInfo("remove@example.com", removeKey, []string{"10.63.0.3/32"})})

	applyCalls := 0
	wg := &WireGuard{
		config:       cfg,
		peerStore:    ps,
		statsTracker: stats.New(),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				configureDeviceFn: func(interfaceName string, cfg wgtypes.Config) error {
					applyCalls++
					if interfaceName != "wg-test" {
						t.Fatalf("unexpected interface name: %s", interfaceName)
					}
					if !cfg.ReplacePeers {
						t.Fatal("expected ReplacePeers=true")
					}
					if len(cfg.Peers) != 2 {
						t.Fatalf("expected 2 peers in full snapshot, got %d", len(cfg.Peers))
					}
					keys := map[string]struct{}{}
					for _, peer := range cfg.Peers {
						keys[peer.PublicKey.String()] = struct{}{}
					}
					if _, ok := keys[keepKey]; !ok {
						t.Fatal("expected keep key in replace snapshot")
					}
					if _, ok := keys[newKey]; !ok {
						t.Fatal("expected new key in replace snapshot")
					}
					if _, ok := keys[removeKey]; ok {
						t.Fatal("did not expect stale key in replace snapshot")
					}
					return nil
				},
			},
		},
		state: lifecycleRunning,
	}

	wg.statsTracker.UpdateStatsBatch([]stats.Sample{
		{
			PublicKey:  removeKey,
			Email:      "remove@example.com",
			Rx:         100,
			Tx:         50,
			EndpointIP: "1.1.1.1",
		},
	})

	users := []*common.User{
		{
			Email:    "keep@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: keepKey, PeerIps: []string{"10.63.0.2/32"},
				},
			},
		},
		{
			Email:    "new@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: newKey, PeerIps: []string{"10.63.0.10/32"},
				},
			},
		},
	}

	if err := wg.SyncUsers(context.Background(), users); err != nil {
		t.Fatalf("SyncUsers failed: %v", err)
	}

	if applyCalls != 1 {
		t.Fatalf("expected one replace apply call, got %d", applyCalls)
	}

	if peer := wg.peerStore.GetByKey(keepKey); peer == nil {
		t.Fatal("expected keep key to remain in config")
	}
	if peer := wg.peerStore.GetByKey(newKey); peer == nil {
		t.Fatal("expected new key to exist in config")
	}
	if peer := wg.peerStore.GetByKey(removeKey); peer != nil {
		t.Fatal("expected stale key removed from config")
	}

	entry := wg.statsTracker.GetStatsEntries([]string{removeKey})[removeKey]
	if entry == nil {
		t.Fatal("expected stale stats entry to remain marked deleted until reset")
	}
	if !entry.IsDeleted {
		t.Fatal("expected stale stats entry to be marked deleted")
	}
}

func TestSyncUsersNoEffectiveChangeSkipsReplaceApply(t *testing.T) {
	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.64.0.1/24"]
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, key, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	ps := NewPeerStore()
	ps.ReplaceAll([]*PeerInfo{mustPeerInfo("keep@example.com", key, []string{"10.64.0.2/32"})})

	applyCalls := 0
	wg := &WireGuard{
		config:       cfg,
		peerStore:    ps,
		statsTracker: stats.New(),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				configureDeviceFn: func(interfaceName string, cfg wgtypes.Config) error {
					applyCalls++
					return nil
				},
			},
		},
		state: lifecycleRunning,
	}

	users := []*common.User{
		{
			Email:    "keep@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: key, PeerIps: []string{"10.64.0.2/32"},
				},
			},
		},
	}

	if err := wg.SyncUsers(context.Background(), users); err != nil {
		t.Fatalf("SyncUsers failed: %v", err)
	}

	if applyCalls != 0 {
		t.Fatalf("expected no ConfigureDevice calls for no-op full sync, got %d", applyCalls)
	}
}

func TestUpdateUsersNoEffectiveChangeSkipsApply(t *testing.T) {
	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.65.0.1/24"]
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, key, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	ps := NewPeerStore()
	ps.ReplaceAll([]*PeerInfo{mustPeerInfo("keep@example.com", key, []string{"10.65.0.2/32"})})

	applyCalls := 0
	wg := &WireGuard{
		config:       cfg,
		peerStore:    ps,
		statsTracker: stats.New(),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				configureDeviceFn: func(interfaceName string, cfg wgtypes.Config) error {
					applyCalls++
					return nil
				},
			},
		},
		state: lifecycleRunning,
	}

	users := []*common.User{
		{
			Email:    "keep@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: key, PeerIps: []string{"10.65.0.2/32"},
				},
			},
		},
	}

	if err := wg.UpdateUsers(context.Background(), users); err != nil {
		t.Fatalf("UpdateUsers failed: %v", err)
	}

	if applyCalls != 0 {
		t.Fatalf("expected no ConfigureDevice calls for no-op partial sync, got %d", applyCalls)
	}
}

func TestUpdateUsersDuplicateEmailUsesLastEntry(t *testing.T) {
	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.66.0.1/24"]
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, oldKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate old key: %v", err)
	}
	_, newKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate new key: %v", err)
	}

	ps := NewPeerStore()
	ps.ReplaceAll([]*PeerInfo{mustPeerInfo("user@example.com", oldKey, []string{"10.66.0.2/32"})})

	applyCalls := 0
	wg := &WireGuard{
		config:       cfg,
		peerStore:    ps,
		statsTracker: stats.New(),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				configureDeviceFn: func(interfaceName string, cfg wgtypes.Config) error {
					applyCalls++
					return nil
				},
			},
		},
		state: lifecycleRunning,
	}

	users := []*common.User{
		{
			Email:    "user@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: oldKey, PeerIps: []string{"10.66.0.2/32"},
				},
			},
		},
		{
			Email:    "user@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: newKey, PeerIps: []string{"10.66.0.2/32"},
				},
			},
		},
	}

	if err := wg.UpdateUsers(context.Background(), users); err != nil {
		t.Fatalf("UpdateUsers failed: %v", err)
	}

	if applyCalls != 1 {
		t.Fatalf("expected one ConfigureDevice call for effective change, got %d", applyCalls)
	}

	if peer := wg.peerStore.GetByKey(oldKey); peer != nil {
		t.Fatal("expected old key to be removed")
	}
	if peer := wg.peerStore.GetByKey(newKey); peer == nil {
		t.Fatal("expected new key to be present")
	}
}

func TestUpdateUsersRejectsKeyOwnedByUntouchedUser(t *testing.T) {
	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.67.0.1/24"]
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, ownedKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	ps := NewPeerStore()
	ps.ReplaceAll([]*PeerInfo{mustPeerInfo("owner@example.com", ownedKey, []string{"10.67.0.2/32"})})

	applyCalls := 0
	wg := &WireGuard{
		config:       cfg,
		peerStore:    ps,
		statsTracker: stats.New(),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				configureDeviceFn: func(interfaceName string, cfg wgtypes.Config) error {
					applyCalls++
					return nil
				},
			},
		},
		state: lifecycleRunning,
	}

	users := []*common.User{
		{
			Email:    "other@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: ownedKey, PeerIps: []string{"10.67.0.3/32"},
				},
			},
		},
	}

	err = wg.UpdateUsers(context.Background(), users)
	if err == nil {
		t.Fatal("expected UpdateUsers to fail when key is owned by untouched user")
	}

	if applyCalls != 0 {
		t.Fatalf("expected no ConfigureDevice call on ownership conflict, got %d", applyCalls)
	}

	ownerPeer := wg.peerStore.GetByKey(ownedKey)
	if ownerPeer == nil || ownerPeer.Email != "owner@example.com" {
		t.Fatal("expected key ownership to remain unchanged")
	}
}

func TestUpdateUsersAllowsKeyTransferWhenBothUsersTouched(t *testing.T) {
	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.68.0.1/24"]
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, oldKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate old key: %v", err)
	}
	_, newKeyForOld, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate new key for old user: %v", err)
	}

	ps := NewPeerStore()
	ps.ReplaceAll([]*PeerInfo{mustPeerInfo("old@example.com", oldKey, []string{"10.68.0.2/32"})})

	applyCalls := 0
	wg := &WireGuard{
		config:       cfg,
		peerStore:    ps,
		statsTracker: stats.New(),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				configureDeviceFn: func(interfaceName string, cfg wgtypes.Config) error {
					applyCalls++
					return nil
				},
			},
		},
		state: lifecycleRunning,
	}

	// old@example.com rotates to a new key; new@example.com claims the original key.
	// Both users have valid credentials, so both appear in touchedEmails and the
	// ownership transfer is permitted.
	users := []*common.User{
		{
			Email:    "old@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: newKeyForOld, PeerIps: []string{"10.68.0.3/32"},
				},
			},
		},
		{
			Email:    "new@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: oldKey, PeerIps: []string{"10.68.0.2/32"},
				},
			},
		},
	}

	if err := wg.UpdateUsers(context.Background(), users); err != nil {
		t.Fatalf("UpdateUsers failed: %v", err)
	}

	peer := wg.peerStore.GetByKey(oldKey)
	if peer == nil {
		t.Fatal("expected original key to remain in config under new owner")
	}
	if peer.Email != "new@example.com" {
		t.Fatalf("expected original key owner to be new@example.com, got %s", peer.Email)
	}
	if peer = wg.peerStore.GetByKey(newKeyForOld); peer == nil {
		t.Fatal("expected old user's new key to be in config")
	}
	if peer.Email != "old@example.com" {
		t.Fatalf("expected new key owner to be old@example.com, got %s", peer.Email)
	}
}

func TestSyncUsersRejectsDuplicateIPsAcrossUsers(t *testing.T) {
	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.69.0.1/24"]
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, key1, _ := GenerateKeyPair()
	_, key2, _ := GenerateKeyPair()

	wg := &WireGuard{
		config:       cfg,
		peerStore:    NewPeerStore(),
		statsTracker: stats.New(),
		state:        lifecycleRunning,
	}

	users := []*common.User{
		{
			Email:    "user1@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: key1, PeerIps: []string{"10.69.0.2/32"},
				},
			},
		},
		{
			Email:    "user2@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: key2, PeerIps: []string{"10.69.0.2/32"},
				},
			},
		},
	}

	err = wg.SyncUsers(context.Background(), users)
	if err == nil {
		t.Fatal("expected error for duplicate IPs")
	}
	if !strings.Contains(err.Error(), "duplicate wireguard allowed IP") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpdateUsersChangesAllowedIP(t *testing.T) {
	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.70.0.1/24"]
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, key, _ := GenerateKeyPair()

	ps := NewPeerStore()
	ps.ReplaceAll([]*PeerInfo{mustPeerInfo("keep@example.com", key, []string{"10.70.0.2/32"})})

	applyCalls := 0
	wg := &WireGuard{
		config:       cfg,
		peerStore:    ps,
		statsTracker: stats.New(),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				configureDeviceFn: func(interfaceName string, cfg wgtypes.Config) error {
					applyCalls++
					if cfg.Peers[0].AllowedIPs[0].String() != "10.70.0.3/32" {
						t.Fatal("expected new IP in config")
					}
					return nil
				},
			},
		},
		state: lifecycleRunning,
	}

	users := []*common.User{
		{
			Email:    "keep@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: key, PeerIps: []string{"10.70.0.3/32"},
				},
			},
		},
	}

	if err := wg.UpdateUsers(context.Background(), users); err != nil {
		t.Fatalf("UpdateUsers failed: %v", err)
	}

	if applyCalls != 1 {
		t.Fatalf("expected one ConfigureDevice calls for IP change partial sync, got %d", applyCalls)
	}
}

func TestUpdateUsersAndRestartReappliesKeepaliveToAllPeers(t *testing.T) {
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate interface key: %v", err)
	}

	cfg, err := NewConfig(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.71.0.1/24"],
		"peer_keepalive_seconds": 0,
		"private_key":"` + privateKey + `"
	}`)
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	_, touchedKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate touched key: %v", err)
	}
	_, untouchedKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate untouched key: %v", err)
	}

	ps := NewPeerStore()
	ps.ReplaceAll([]*PeerInfo{
		mustPeerInfo("touched@example.com", touchedKey, []string{"10.71.0.2/32"}),
		mustPeerInfo("untouched@example.com", untouchedKey, []string{"10.71.0.3/32"}),
	})

	var configureCalls []wgtypes.Config
	wg := &WireGuard{
		config:       cfg,
		peerStore:    ps,
		statsTracker: stats.New(),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				configureDeviceFn: func(interfaceName string, cfg wgtypes.Config) error {
					if interfaceName != "wg-test" {
						t.Fatalf("unexpected interface name: %s", interfaceName)
					}
					configureCalls = append(configureCalls, cfg)
					return nil
				},
			},
		},
		state: lifecycleRunning,
	}

	users := []*common.User{
		{
			Email:    "touched@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: touchedKey, PeerIps: []string{"10.71.0.2/32"},
				},
			},
		},
	}

	if err := wg.UpdateUsersAndRestart(context.Background(), users); err != nil {
		t.Fatalf("UpdateUsersAndRestart failed: %v", err)
	}

	if len(configureCalls) != 1 {
		t.Fatalf("expected one restart ConfigureDevice call, got %d", len(configureCalls))
	}

	restartConfig := configureCalls[0]
	if !restartConfig.ReplacePeers {
		t.Fatal("expected restart path to replace peers")
	}
	if len(restartConfig.Peers) != 2 {
		t.Fatalf("expected restart to include both peers, got %d", len(restartConfig.Peers))
	}

	keys := map[string]wgtypes.PeerConfig{}
	for _, peer := range restartConfig.Peers {
		keys[peer.PublicKey.String()] = peer
		if peer.PersistentKeepaliveInterval == nil {
			t.Fatal("expected persistent keepalive interval to be set explicitly")
		}
		if *peer.PersistentKeepaliveInterval != 0 {
			t.Fatalf("expected keepalive 0, got %v", *peer.PersistentKeepaliveInterval)
		}
	}

	if _, ok := keys[touchedKey]; !ok {
		t.Fatal("expected touched peer in restart config")
	}
	if _, ok := keys[untouchedKey]; !ok {
		t.Fatal("expected untouched peer in restart config")
	}
}

func dummyKey(s string) wgtypes.Key {
	k, err := wgtypes.ParseKey(s)
	if err == nil {
		return k
	}
	var key wgtypes.Key
	copy(key[:], s)
	return key
}

func mustPeerInfo(email, pubStr string, ips []string) *PeerInfo {
	var parsedIPs []net.IPNet
	for _, ip := range ips {
		_, ipNet, _ := net.ParseCIDR(ip)
		if ipNet != nil {
			parsedIPs = append(parsedIPs, *ipNet)
		}
	}
	return &PeerInfo{
		Email:      email,
		PublicKey:  dummyKey(pubStr),
		AllowedIPs: parsedIPs,
	}
}
