package wireguard

import (
	"fmt"
	"sync"
	"testing"

	"github.com/pasarguard/node/common"
	nodeconfig "github.com/pasarguard/node/config"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWireGuardRestartConcurrentWithShutdown(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	wgCfg := mustNewWireGuardConfigForLifecycle(t, fmt.Sprintf(`{
		"interface_name":"wg-test-restart",
		"listen_port":51820,
		"address":["10.91.0.1/24"],
		"private_key":"%s"
	}`, privateKey))

	users := []*common.User{
		{
			Email:    "user@example.com",
			Inbounds: []string{"wg-test-restart"},
			Proxies: &common.Proxy{
				Wireguard: &common.Wireguard{
					PublicKey: publicKey, PeerIps: []string{"10.91.0.2/32"},
				},
			},
		},
	}

	managerFactory := func(string) (*Manager, error) {
		return &Manager{
			iFaceName: "wg-test-restart",
			client:    &fakeWGClient{},
			nl: mockNetlinkOps{
				parseAddrFn: func(_ string) (*netlink.Addr, error) { return nil, nil },
				linkAddFn:   func(_ netlink.Link) error { return nil },
				linkByName: func(name string) (netlink.Link, error) {
					return nil, nil
				},
				addrAddFn:   func(_ netlink.Link, _ *netlink.Addr) error { return nil },
				linkSetUpFn: func(_ netlink.Link) error { return nil },
				linkDelFn:   func(_ netlink.Link) error { return nil },
			},
			configure: func(_ wgClient, _ string, cfg wgtypes.Config) error {
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

	var wgWait sync.WaitGroup
	wgWait.Add(2)

	go func() {
		defer wgWait.Done()
		for i := 0; i < 10; i++ {
			_ = wg.Restart()
		}
	}()

	go func() {
		defer wgWait.Done()
		wg.Shutdown()
	}()

	wgWait.Wait()
}
