package wireguard

import (
	"errors"
	"fmt"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wgClient interface {
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Device(name string) (*wgtypes.Device, error)
	Close() error
}

type netlinkOps interface {
	ParseAddr(string) (*netlink.Addr, error)
	LinkAdd(netlink.Link) error
	LinkByName(string) (netlink.Link, error)
	AddrAdd(netlink.Link, *netlink.Addr) error
	LinkSetUp(netlink.Link) error
	LinkDel(netlink.Link) error
}

type defaultNetlinkOps struct{}

func (defaultNetlinkOps) ParseAddr(address string) (*netlink.Addr, error) {
	return netlink.ParseAddr(address)
}

func (defaultNetlinkOps) LinkAdd(link netlink.Link) error {
	return netlink.LinkAdd(link)
}

func (defaultNetlinkOps) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func (defaultNetlinkOps) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrAdd(link, addr)
}

func (defaultNetlinkOps) LinkSetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func (defaultNetlinkOps) LinkDel(link netlink.Link) error {
	return netlink.LinkDel(link)
}

type configureDeviceFunc func(client wgClient, interfaceName string, config wgtypes.Config) error

func defaultConfigureDevice(client wgClient, interfaceName string, config wgtypes.Config) error {
	return client.ConfigureDevice(interfaceName, config)
}

func wrapPermissionDeniedError(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return fmt.Errorf(
			"%s: permission denied; WireGuard requires CAP_NET_ADMIN and kernel support on the host (if running in Docker, add NET_ADMIN and ensure the wireguard kernel module is available on the host): %w",
			action,
			err,
		)
	}
	return err
}

// Manager handles WireGuard interface management using wgctrl
type Manager struct {
	client    wgClient
	iFaceName string
	nl        netlinkOps
	configure configureDeviceFunc
	mu        sync.RWMutex
}

// NewManager creates a new WireGuard manager
func NewManager(interfaceName string) (*Manager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create wgctrl client: %w", err)
	}

	return &Manager{
		client:    client,
		iFaceName: interfaceName,
		nl:        defaultNetlinkOps{},
		configure: defaultConfigureDevice,
	}, nil
}

func (m *Manager) getNetlinkOps() netlinkOps {
	if m.nl == nil {
		return defaultNetlinkOps{}
	}
	return m.nl
}

func (m *Manager) getConfigureDevice() configureDeviceFunc {
	if m.configure == nil {
		return defaultConfigureDevice
	}
	return m.configure
}

func buildInitialWGConfig(privateKey wgtypes.Key, listenPort int, peers []wgtypes.PeerConfig) wgtypes.Config {
	config := wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &listenPort,
	}

	if len(peers) > 0 {
		config.Peers = peers
		config.ReplacePeers = true
	}

	return config
}

// InitializeWithPeers sets up the WireGuard interface with initial configuration and optional full peer snapshot.
func (m *Manager) InitializeWithPeers(privateKey wgtypes.Key, listenPort int, serverIPs []string, peers []wgtypes.PeerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client == nil {
		return fmt.Errorf("wgctrl client is not initialized")
	}

	nl := m.getNetlinkOps()
	configure := m.getConfigureDevice()

	var parsedAddrs []*netlink.Addr
	for _, ipStr := range serverIPs {
		addr, err := nl.ParseAddr(ipStr)
		if err != nil {
			return fmt.Errorf("failed to parse address %s: %w", ipStr, err)
		}
		parsedAddrs = append(parsedAddrs, addr)
	}

	// Clean up any existing interface
	if err := m.cleanupExistingInterface(); err != nil {
		return fmt.Errorf("failed to cleanup existing interface: %w", err)
	}

	// Create WireGuard interface
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: m.iFaceName}}
	if err := nl.LinkAdd(link); err != nil {
		return fmt.Errorf("failed to add link: %w", wrapPermissionDeniedError("creating wireguard interface", err))
	}
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			_ = m.cleanupExistingInterface()
		}
	}()

	// Configure WireGuard (single call for base settings + optional peers snapshot).
	config := buildInitialWGConfig(privateKey, listenPort, peers)

	if err := configure(m.client, m.iFaceName, config); err != nil {
		return fmt.Errorf("failed to configure device: %w", wrapPermissionDeniedError("configuring wireguard device", err))
	}

	link2, err := nl.LinkByName(m.iFaceName)
	if err != nil {
		return fmt.Errorf("failed to get link: %w", err)
	}

	for _, addr := range parsedAddrs {
		if err := nl.AddrAdd(link2, addr); err != nil {
			return fmt.Errorf(
				"failed to add address %s: %w",
				addr.IPNet.String(),
				wrapPermissionDeniedError("assigning wireguard interface address", err),
			)
		}
	}

	// Bring interface up
	if err := nl.LinkSetUp(link2); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", wrapPermissionDeniedError("bringing wireguard interface up", err))
	}

	cleanupOnError = false
	return nil
}

// ApplyPeers applies a batch of peer configurations in a single kernel call.
func (m *Manager) ApplyPeers(peers []wgtypes.PeerConfig) error {
	if len(peers) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client == nil {
		return fmt.Errorf("wgctrl client is not initialized")
	}

	return m.client.ConfigureDevice(m.iFaceName, wgtypes.Config{Peers: peers})
}

// ApplyPeersReplaceAll applies peers as an authoritative full snapshot in a single kernel call.
func (m *Manager) ApplyPeersReplaceAll(peers []wgtypes.PeerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client == nil {
		return fmt.Errorf("wgctrl client is not initialized")
	}

	return m.client.ConfigureDevice(m.iFaceName, wgtypes.Config{
		Peers:        peers,
		ReplacePeers: true,
	})
}

// ApplyConfig safely configures the device with the given configuration under lock.
func (m *Manager) ApplyConfig(config wgtypes.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client == nil {
		return fmt.Errorf("wgctrl client is not initialized")
	}

	configure := m.getConfigureDevice()
	return configure(m.client, m.iFaceName, config)
}

// GetDevice returns the current WireGuard device statistics
func (m *Manager) GetDevice() (*wgtypes.Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.client == nil {
		return nil, fmt.Errorf("wgctrl client is not initialized")
	}

	return m.client.Device(m.iFaceName)
}

// Close cleans up the WireGuard manager and removes the interface
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error

	client := m.client
	m.client = nil

	// Close wgctrl client
	if client != nil {
		if err := client.Close(); err != nil {
			errs = append(errs, fmt.Errorf("client close: %w", err))
		}
	}

	// Remove interface
	if err := m.cleanupExistingInterface(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// cleanupExistingInterface removes existing interface if it exists
func (m *Manager) cleanupExistingInterface() error {
	nl := m.getNetlinkOps()
	link, err := nl.LinkByName(m.iFaceName)
	if err != nil {
		// Interface doesn't exist, no need to clean up.
		var notFoundErr netlink.LinkNotFoundError
		if errors.As(err, &notFoundErr) {
			return nil
		}
		return fmt.Errorf("link lookup: %w", err)
	}

	if err := nl.LinkDel(link); err != nil {
		return fmt.Errorf("link delete: %w", wrapPermissionDeniedError("deleting wireguard interface", err))
	}

	return nil
}

// GetInterfaceStats returns RX/TX statistics for the interface
func (m *Manager) GetInterfaceStats() (rxBytes, txBytes int64, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	nl := m.getNetlinkOps()
	link, err := nl.LinkByName(m.iFaceName)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get link: %w", err)
	}

	stats := link.Attrs().Statistics
	if stats == nil {
		return 0, 0, nil
	}

	return int64(stats.RxBytes), int64(stats.TxBytes), nil
}
