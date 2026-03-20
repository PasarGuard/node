package wireguard

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func linkNotFoundError() error {
	var err netlink.LinkNotFoundError
	return err
}

type fakeWGClient struct {
	configureDeviceFn func(name string, cfg wgtypes.Config) error
	deviceFn          func(name string) (*wgtypes.Device, error)
	closeFn           func() error
}

func (c *fakeWGClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	if c.configureDeviceFn == nil {
		return nil
	}
	return c.configureDeviceFn(name, cfg)
}

func (c *fakeWGClient) Device(name string) (*wgtypes.Device, error) {
	if c.deviceFn == nil {
		return &wgtypes.Device{}, nil
	}
	return c.deviceFn(name)
}

func (c *fakeWGClient) Close() error {
	if c.closeFn == nil {
		return nil
	}
	return c.closeFn()
}

type mockNetlinkOps struct {
	parseAddrFn func(string) (*netlink.Addr, error)
	linkAddFn   func(netlink.Link) error
	linkByName  func(string) (netlink.Link, error)
	addrAddFn   func(netlink.Link, *netlink.Addr) error
	linkSetUpFn func(netlink.Link) error
	linkDelFn   func(netlink.Link) error
}

func (m mockNetlinkOps) ParseAddr(address string) (*netlink.Addr, error) {
	if m.parseAddrFn == nil {
		return nil, errors.New("ParseAddr was not mocked")
	}
	return m.parseAddrFn(address)
}

func (m mockNetlinkOps) LinkAdd(link netlink.Link) error {
	if m.linkAddFn == nil {
		return errors.New("LinkAdd was not mocked")
	}
	return m.linkAddFn(link)
}

func (m mockNetlinkOps) LinkByName(name string) (netlink.Link, error) {
	if m.linkByName == nil {
		return nil, errors.New("LinkByName was not mocked")
	}
	return m.linkByName(name)
}

func (m mockNetlinkOps) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	if m.addrAddFn == nil {
		return errors.New("AddrAdd was not mocked")
	}
	return m.addrAddFn(link, addr)
}

func (m mockNetlinkOps) LinkSetUp(link netlink.Link) error {
	if m.linkSetUpFn == nil {
		return errors.New("LinkSetUp was not mocked")
	}
	return m.linkSetUpFn(link)
}

func (m mockNetlinkOps) LinkDel(link netlink.Link) error {
	if m.linkDelFn == nil {
		return errors.New("LinkDel was not mocked")
	}
	return m.linkDelFn(link)
}

func TestManagerInitializeConfigureFailureCleansInterface(t *testing.T) {
	linkByNameCalls := 0
	linkDelCalls := 0

	mock := mockNetlinkOps{
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
			return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}, nil
		},
		addrAddFn: func(_ netlink.Link, _ *netlink.Addr) error {
			return nil
		},
		linkSetUpFn: func(_ netlink.Link) error {
			return nil
		},
		linkDelFn: func(_ netlink.Link) error {
			linkDelCalls++
			return nil
		},
	}

	manager := &Manager{
		iFaceName: "wg-test",
		client:    &fakeWGClient{},
		nl:        mock,
		configure: func(_ wgClient, _ string, _ wgtypes.Config) error {
			return errors.New("configure boom")
		},
	}
	err := manager.InitializeWithPeers(wgtypes.Key{}, 51820, []string{"10.0.0.1/24"}, nil)
	if err == nil {
		t.Fatal("expected initialize error, got nil")
	}
	if !strings.Contains(err.Error(), "configure boom") {
		t.Fatalf("unexpected error: %v", err)
	}
	if linkDelCalls != 1 {
		t.Fatalf("expected cleanup link delete to be called once, got %d", linkDelCalls)
	}
}

func TestManagerInitializeAddrAddFailureCleansInterface(t *testing.T) {
	linkByNameCalls := 0
	linkDelCalls := 0

	mock := mockNetlinkOps{
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
				LinkAttrs: netlink.LinkAttrs{Name: name, Flags: net.FlagUp},
			}, nil
		},
		addrAddFn: func(_ netlink.Link, _ *netlink.Addr) error {
			return errors.New("addr add boom")
		},
		linkSetUpFn: func(_ netlink.Link) error {
			return nil
		},
		linkDelFn: func(_ netlink.Link) error {
			linkDelCalls++
			return nil
		},
	}

	manager := &Manager{
		iFaceName: "wg-test",
		client:    &fakeWGClient{},
		nl:        mock,
		configure: func(_ wgClient, _ string, _ wgtypes.Config) error {
			return nil
		},
	}
	err := manager.InitializeWithPeers(wgtypes.Key{}, 51820, []string{"10.0.0.1/24"}, nil)
	if err == nil {
		t.Fatal("expected initialize error, got nil")
	}
	if !strings.Contains(err.Error(), "addr add boom") {
		t.Fatalf("unexpected error: %v", err)
	}
	if linkDelCalls != 1 {
		t.Fatalf("expected cleanup link delete to be called once, got %d", linkDelCalls)
	}
}

func TestManagerInitializeWithPeersConfiguresReplacePeers(t *testing.T) {
	linkByNameCalls := 0
	configureCalls := 0

	_, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	parsedKey, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
	peers := []wgtypes.PeerConfig{
		{PublicKey: parsedKey},
	}

	mock := mockNetlinkOps{
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
				LinkAttrs: netlink.LinkAttrs{Name: name, Flags: net.FlagUp},
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
	}

	manager := &Manager{
		iFaceName: "wg-test",
		client:    &fakeWGClient{},
		nl:        mock,
		configure: func(_ wgClient, _ string, cfg wgtypes.Config) error {
			configureCalls++
			if cfg.PrivateKey == nil {
				t.Fatal("expected private key to be set")
			}
			if cfg.ListenPort == nil {
				t.Fatal("expected listen port to be set")
			}
			if !cfg.ReplacePeers {
				t.Fatal("expected ReplacePeers=true for initialize with peers")
			}
			if len(cfg.Peers) != len(peers) {
				t.Fatalf("unexpected peers length: got %d want %d", len(cfg.Peers), len(peers))
			}
			return nil
		},
	}

	err = manager.InitializeWithPeers(wgtypes.Key{}, 51820, []string{"10.0.0.1/24"}, peers)
	if err != nil {
		t.Fatalf("unexpected initialize error: %v", err)
	}
	if configureCalls != 1 {
		t.Fatalf("expected one configure call, got %d", configureCalls)
	}
}

func TestManagerCleanupExistingInterfaceReturnsLookupError(t *testing.T) {
	manager := &Manager{
		iFaceName: "wg-test",
		nl: mockNetlinkOps{
			linkByName: func(_ string) (netlink.Link, error) {
				return nil, errors.New("permission denied")
			},
		},
	}

	err := manager.cleanupExistingInterface()
	if err == nil {
		t.Fatal("expected cleanup error, got nil")
	}
	if !strings.Contains(err.Error(), "link lookup") {
		t.Fatalf("unexpected cleanup error: %v", err)
	}
}

func TestManagerInitializeNilClient(t *testing.T) {
	manager := &Manager{
		iFaceName: "wg-test",
	}

	err := manager.InitializeWithPeers(wgtypes.Key{}, 51820, []string{"10.0.0.1/24"}, nil)
	if err == nil {
		t.Fatal("expected initialize error, got nil")
	}
	if !strings.Contains(err.Error(), "wgctrl client is not initialized") {
		t.Fatalf("unexpected initialize error: %v", err)
	}
}

func TestManagerGetDeviceNilClient(t *testing.T) {
	manager := &Manager{
		iFaceName: "wg-test",
	}

	_, err := manager.GetDevice()
	if err == nil {
		t.Fatal("expected get device error, got nil")
	}
	if !strings.Contains(err.Error(), "wgctrl client is not initialized") {
		t.Fatalf("unexpected get device error: %v", err)
	}
}

func TestManagerApplyPeersReplaceAllSetsReplacePeers(t *testing.T) {
	calls := 0
	manager := &Manager{
		iFaceName: "wg-test",
		client: &fakeWGClient{
			configureDeviceFn: func(name string, cfg wgtypes.Config) error {
				calls++
				if name != "wg-test" {
					t.Fatalf("unexpected interface: %s", name)
				}
				if !cfg.ReplacePeers {
					t.Fatal("expected ReplacePeers=true")
				}
				if len(cfg.Peers) != 1 {
					t.Fatalf("expected one peer config, got %d", len(cfg.Peers))
				}
				return nil
			},
		},
	}

	_, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	parsed, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}

	err = manager.ApplyPeersReplaceAll([]wgtypes.PeerConfig{
		{PublicKey: parsed},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected one configure call, got %d", calls)
	}
}

func TestManagerApplyPeersReplaceAllNilClient(t *testing.T) {
	manager := &Manager{iFaceName: "wg-test"}
	err := manager.ApplyPeersReplaceAll(nil)
	if err == nil {
		t.Fatal("expected error with nil client")
	}
	if !strings.Contains(err.Error(), "wgctrl client is not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}
