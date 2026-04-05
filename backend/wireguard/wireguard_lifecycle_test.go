package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	nodeconfig "github.com/pasarguard/node/config"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustNewWireGuardConfigForLifecycle(t *testing.T, raw string) *Config {
	t.Helper()

	cfg, err := NewConfig(raw)
	if err != nil {
		t.Fatalf("failed to create wireguard config: %v", err)
	}

	return cfg
}

func mustGeneratePublicKey(t *testing.T) string {
	t.Helper()

	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	return pub
}

func TestWireGuardNewRejectsInvalidPrivateKeyBeforeManagerInit(t *testing.T) {
	wgCfg := mustNewWireGuardConfigForLifecycle(t, `{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.99.0.1/24"],
		"private_key":"invalid-key"
	}`)

	cfg := &nodeconfig.Config{
		LogBufferSize:               1,
		StatsUpdateIntervalSeconds:  10,
		StatsCleanupIntervalSeconds: 10,
	}

	_, err := New(cfg, wgCfg, nil)
	if err == nil {
		t.Fatal("expected startup failure for invalid private key")
	}
	if !strings.Contains(err.Error(), "invalid wireguard private key") {
		t.Fatalf("unexpected startup error: %v", err)
	}
}

func TestWireGuardNewInitializesWithSingleConfigureCallIncludingPeers(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	wgCfg := mustNewWireGuardConfigForLifecycle(t, fmt.Sprintf(`{
		"interface_name":"wg-test",
		"listen_port":51820,
		"address":["10.91.0.1/24"],
		"private_key":"%s"
	}`, privateKey))

	users := []*common.User{
		{
			Email:    "user@example.com",
			Inbounds: []string{"wg-test"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: publicKey, PeerIps: []string{"10.91.0.2/32"},
				},
			},
		},
	}

	ctx := context.WithValue(context.Background(), backend.ConfigKey{}, wgCfg)
	ctx = context.WithValue(ctx, backend.UsersKey{}, users)

	configureCalls := 0
	var configured wgtypes.Config
	linkByNameCalls := 0

	managerFactory := func(string) (*Manager, error) {
		return &Manager{
			iFaceName: "wg-test",
			client:    &fakeWGClient{},
			nl: mockNetlinkOps{
				parseAddrFn: func(_ string) (*netlink.Addr, error) {
					return &netlink.Addr{}, nil
				},
				linkAddFn: func(_ netlink.Link) error {
					return nil
				},
				linkByName: func(name string) (netlink.Link, error) {
					linkByNameCalls++
					if linkByNameCalls == 1 {
						return nil, linkNotFoundError()
					}
					return &netlink.Dummy{
						LinkAttrs: netlink.LinkAttrs{
							Name:  name,
							Flags: net.FlagUp,
						},
					}, nil
				},
				addrAddFn: func(_ netlink.Link, _ *netlink.Addr) error {
					return nil
				},
				linkSetUpFn: func(_ netlink.Link) error {
					return nil
				},
				linkDelFn: func(_ netlink.Link) error {
					return nil
				},
			},
			configure: func(_ wgClient, _ string, cfg wgtypes.Config) error {
				configureCalls++
				configured = cfg
				return nil
			},
		}, nil
	}

	cfg := &nodeconfig.Config{
		LogBufferSize:               1,
		StatsUpdateIntervalSeconds:  10,
		StatsCleanupIntervalSeconds: 10,
	}

	wg, err := newWithManagerFactory(cfg, wgCfg, users, managerFactory)
	if err != nil {
		t.Fatalf("expected startup success, got error: %v", err)
	}
	defer wg.Shutdown()

	if configureCalls != 1 {
		t.Fatalf("expected exactly one configure call during startup, got %d", configureCalls)
	}
	if configured.PrivateKey == nil || configured.ListenPort == nil {
		t.Fatal("expected startup configure call to include base interface config")
	}
	if !configured.ReplacePeers {
		t.Fatal("expected startup configure call to include ReplacePeers=true")
	}
	if len(configured.Peers) != 1 {
		t.Fatalf("expected one peer in startup configure call, got %d", len(configured.Peers))
	}

	select {
	case startupLog := <-wg.Logs():
		pattern := regexp.MustCompile(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d{6} \[Info\] WireGuard interface wg-test initialized successfully$`)
		if !pattern.MatchString(startupLog) {
			t.Fatalf("expected startup log with timestamp prefix, got %q", startupLog)
		}
	case <-time.After(time.Second):
		t.Fatal("expected startup log to be emitted")
	}

	parsedPublicKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
	if configured.Peers[0].PublicKey != parsedPublicKey {
		t.Fatal("unexpected peer key in startup configure payload")
	}
}

func TestWireGuardShutdownIsIdempotent(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	logChan := make(chan string)

	wg := &WireGuard{
		cancelFunc:    cancel,
		logChan:       logChan,
		updateTicker:  time.NewTicker(time.Hour),
		cleanupTicker: time.NewTicker(time.Hour),
		state:         lifecycleRunning,
		version:       "v-test",
	}

	wg.Shutdown()

	select {
	case _, ok := <-logChan:
		if ok {
			t.Fatal("expected log channel to be closed after first shutdown")
		}
	default:
		t.Fatal("expected log channel close signal after first shutdown")
	}

	// Must not panic or alter state unexpectedly on second call.
	wg.Shutdown()

	if wg.state != lifecycleStopped {
		t.Fatalf("expected lifecycleStopped after shutdown, got %v", wg.state)
	}
	if wg.version != "" {
		t.Fatalf("expected empty version after shutdown, got %q", wg.version)
	}
	if wg.logChan != nil {
		t.Fatal("expected wg.logChan to be nil after shutdown")
	}
}

func TestBuildPeerConfigsForRestartRejectsPeersWithoutValidAllowedIPs(t *testing.T) {
	validKey := mustGeneratePublicKey(t)
	invalidKey := mustGeneratePublicKey(t)

	peers := []*PeerInfo{
		mustPeerInfo("valid@example.com", validKey, []string{"10.77.0.2/32"}),
		mustPeerInfo("invalid@example.com", invalidKey, []string{"not-a-cidr"}),
	}

	if _, err := buildPeerConfigsForRestart(peers, nil); err == nil {
		t.Fatal("expected error for peer with invalid allowed IP")
	}
}

func TestBuildPeerConfigsForRestartOrdersPeersDeterministically(t *testing.T) {
	keyA := mustGeneratePublicKey(t)
	keyB := mustGeneratePublicKey(t)
	keyC := mustGeneratePublicKey(t)

	expected := []string{keyA, keyB, keyC}
	slices.Sort(expected)

	peers := []*PeerInfo{
		mustPeerInfo("c@example.com", keyC, []string{"10.78.0.2/32"}),
		mustPeerInfo("a@example.com", keyA, []string{"10.78.0.3/32"}),
		mustPeerInfo("b@example.com", keyB, []string{"10.78.0.4/32"}),
	}

	cfgs, err := buildPeerConfigsForRestart(peers, nil)
	if err != nil {
		t.Fatalf("buildPeerConfigsForRestart failed: %v", err)
	}
	if len(cfgs) != len(expected) {
		t.Fatalf("expected %d peer configs, got %d", len(expected), len(cfgs))
	}

	for i, cfg := range cfgs {
		if cfg.PublicKey.String() != expected[i] {
			t.Fatalf("expected key %s at index %d, got %s", expected[i], i, cfg.PublicKey.String())
		}
	}
}

func TestGetSysStatsRejectsWhenNotStarted(t *testing.T) {
	wg := &WireGuard{
		state: lifecycleStopped,
	}

	_, err := wg.GetSysStats(context.Background())
	if err == nil {
		t.Fatal("expected error when backend is not started")
	}
	if !strings.Contains(err.Error(), "wireguard not started") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetSysStatsRejectsWhenKernelUnhealthy(t *testing.T) {
	wg := &WireGuard{
		state: lifecycleRunning,
		manager: &Manager{
			iFaceName: "wg-test",
			nl: mockNetlinkOps{
				linkByName: func(string) (netlink.Link, error) {
					return nil, errors.New("link missing")
				},
			},
		},
	}

	_, err := wg.GetSysStats(context.Background())
	if err == nil {
		t.Fatal("expected error when kernel health check fails")
	}
	if !strings.Contains(err.Error(), "wireguard interface not available") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetSysStatsReturnsStatsWhenKernelHealthy(t *testing.T) {
	wg := &WireGuard{
		state:     lifecycleRunning,
		startTime: time.Now().Add(-2 * time.Second),
		manager: &Manager{
			iFaceName: "wg-test",
			client: &fakeWGClient{
				deviceFn: func(string) (*wgtypes.Device, error) {
					return &wgtypes.Device{}, nil
				},
			},
			nl: mockNetlinkOps{
				linkByName: func(name string) (netlink.Link, error) {
					return &netlink.Dummy{
						LinkAttrs: netlink.LinkAttrs{
							Name:  name,
							Flags: net.FlagUp,
						},
					}, nil
				},
			},
		},
	}

	stats, err := wg.GetSysStats(context.Background())
	if err != nil {
		t.Fatalf("expected sys stats success, got error: %v", err)
	}
	if stats == nil {
		t.Fatal("expected non-nil sys stats response")
	}
	if stats.GetNumGoroutine() == 0 {
		t.Fatal("expected runtime goroutine count to be populated")
	}
	if stats.GetUptime() == 0 {
		t.Fatal("expected non-zero uptime")
	}
}
