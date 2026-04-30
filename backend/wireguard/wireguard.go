package wireguard

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/stats"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type newManagerFunc func(interfaceName string) (*Manager, error)

type lifecycleState uint8

const (
	lifecycleStopped lifecycleState = iota
	lifecycleStarting
	lifecycleRunning
)

var (
	errWireGuardNotStarted            = errors.New("wireguard not started")
	errWireGuardManagerNotInitialized = errors.New("wireguard manager not initialized")
)

// WireGuard locking hierarchy — must always be acquired in this order:
//
//	wg.syncMu  serialises all peer sync/remove operations
//	wg.mu      guards lifecycle state (manager, state, config, version)
//	m.mu       guards Manager internals (client, configure, nl)
//
// Never acquire an outer lock while holding an inner one.
type WireGuard struct {
	config       *Config
	cfg          *config.Config
	manager      *Manager
	statsTracker *stats.Tracker
	peerStore    *PeerStore

	// Tickers
	updateTicker  *time.Ticker
	cleanupTicker *time.Ticker

	// Stats update config
	updateInterval time.Duration

	logChan        chan string
	cancelFunc     context.CancelFunc
	startTime      time.Time
	version        string
	mu             sync.RWMutex
	state          lifecycleState
	interfaceStats *stats.InterfaceCountersTracker
	shutdownOnce   sync.Once
	syncMu         sync.Mutex
	lastStatsErrAt time.Time
	newManager     newManagerFunc
	hostRouting    func()
}

// getWireGuardVersion fetches the wireguard-tools version
func getWireGuardVersion() string {
	cmd := exec.Command("wg", "--version")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("failed to get wireguard version: %v", err)
		return "unknown"
	}

	// Parse the version from output
	// Expected format: "wireguard-tools v1.0.20200513 - https://git.zx2c4.com/wireguard-tools/"
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		firstLine := strings.TrimSpace(lines[0])
		// Extract version from "wireguard-tools v1.0.20200513 - ..."
		parts := strings.Fields(firstLine)
		if len(parts) >= 2 {
			return parts[1] // Returns "v1.0.20200513"
		}
	}

	return "unknown"
}

func lifecycleReadinessError(state lifecycleState) error {
	switch state {
	case lifecycleRunning:
		return nil
	default:
		return errWireGuardNotStarted
	}
}

func (wg *WireGuard) ensureRunningWithManagerLocked() error {
	if err := lifecycleReadinessError(wg.state); err != nil {
		return err
	}
	if wg.manager == nil {
		return errWireGuardManagerNotInitialized
	}
	return nil
}

// New creates a new WireGuard backend instance
func New(cfg *config.Config, wgConfig *Config, users []*common.User) (*WireGuard, error) {
	return newWithManagerFactory(cfg, wgConfig, users, NewManager)
}

// newWithManagerFactory is an internal constructor seam for tests and controlled startup injection.
// Keep unexported; production callers should use New(...).
func newWithManagerFactory(cfg *config.Config, wgConfig *Config, users []*common.User, managerFactory newManagerFunc) (*WireGuard, error) {
	if managerFactory == nil {
		managerFactory = NewManager
	}

	wgCtx, wgCancel := context.WithCancel(context.Background())

	// Get WireGuard version before starting
	version := getWireGuardVersion()

	wg := &WireGuard{
		cancelFunc:     wgCancel,
		cfg:            cfg,
		statsTracker:   stats.New(),
		interfaceStats: stats.NewInterfaceCountersTracker(),
		peerStore:      NewPeerStore(),
		logChan:        make(chan string, cfg.LogBufferSize),
		startTime:      time.Now(),
		version:        version,
		newManager:     managerFactory,
		state:          lifecycleStarting,
	}

	start := time.Now()

	if wgConfig == nil {
		return nil, errors.New("wireguard config string must not be empty or nil")
	}

	wg.config = wgConfig

	log.Println("config loaded in", time.Since(start).Seconds(), "second.")

	// Validate private key before creating manager.
	// This rejects invalid configured keys during New() with no manager side effects.
	privateKey, err := wgConfig.GetPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("invalid wireguard private key: %w", err)
	}

	normalizedUsers := normalizeUsers(users)
	startupExistingByKey := wg.buildExistingPeersByKeySnapshot()
	startupDesiredPeers, err := wg.collectDesiredPeers(normalizedUsers)
	if err != nil {
		return nil, fmt.Errorf("failed to collect desired peers: %w", err)
	}

	startupDiff, err := wg.buildSyncDiff(startupExistingByKey, startupDesiredPeers)
	if err != nil {
		return nil, fmt.Errorf("failed to build sync diff: %w", err)
	}
	psk, _ := wgConfig.GetPreSharedKey()
	startupPeerConfigs, appliedKeys := buildTargetPeerConfigs(startupDiff.TargetPeers, psk)

	manager, err := wg.newManager(wgConfig.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}

	// Initialize the WireGuard interface with peers in the same kernel configure call.
	if err = manager.InitializeWithPeers(privateKey, wgConfig.ListenPort, wgConfig.Address, startupPeerConfigs); err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to initialize interface: %w", err)
	}

	// After the tunnel exists, apply optional host routing so nft iifname matches the real interface.
	wg.hostRouting = applyLinuxHostRouting(wgConfig.InterfaceName)

	wg.manager = manager

	// Initialize PeerStore with successfully committed peers.
	// We use Init() because the store is empty on startup and there are no users to remove.
	wg.peerStore.Init(filterUpsertsByAppliedKeys(startupDiff.UpsertPeers, appliedKeys))

	// Initialize stats tickers
	wg.initStatsTickers(wgCtx)

	wg.mu.Lock()
	wg.state = lifecycleRunning
	wg.mu.Unlock()

	log.Println("wireguard started, Version:", wg.Version())
	wg.emitInfoLogf("WireGuard interface %s initialized successfully", wgConfig.InterfaceName)

	return wg, nil
}

// Started returns whether the WireGuard backend is running
func (wg *WireGuard) Started() bool {
	wg.mu.RLock()
	defer wg.mu.RUnlock()
	return wg.state == lifecycleRunning
}

// Version returns the WireGuard version
func (wg *WireGuard) Version() string {
	wg.mu.RLock()
	defer wg.mu.RUnlock()
	return wg.version
}

// Logs returns the log channel as a receive-only channel.
// The channel is closed when Shutdown is called; callers should use range
// so they naturally stop reading once it is closed.
func (wg *WireGuard) Logs() <-chan string {
	return wg.logChan
}

// Restart applies a new configuration dynamically to the WireGuard interface without tearing it down.
func (wg *WireGuard) Restart() error {
	// syncMu prevents a concurrent SyncUser/UpdateUsers call from racing between
	// the GetAll() snapshot and the ReplacePeers kernel call, which would silently
	// roll back live peer changes.
	wg.syncMu.Lock()
	defer wg.syncMu.Unlock()

	return wg.restartLocked()
}

func (wg *WireGuard) restartLocked() error {
	wg.mu.RLock()
	cfg := wg.config
	if cfg == nil {
		wg.mu.RUnlock()
		return fmt.Errorf("wireguard config not initialized")
	}

	privateKey, err := cfg.GetPrivateKey()
	if err != nil {
		wg.mu.RUnlock()
		return fmt.Errorf("failed to get private key: %w", err)
	}

	listenPort := cfg.ListenPort
	allPeers := wg.peerStore.GetAll()
	wg.mu.RUnlock()

	psk, _ := wg.config.GetPreSharedKey()
	peerConfigs, err := buildPeerConfigsForRestart(allPeers, psk)
	if err != nil {
		return fmt.Errorf("failed to build restart peer configs: %w", err)
	}

	wg.mu.Lock()
	if err := wg.ensureRunningWithManagerLocked(); err != nil {
		wg.mu.Unlock()
		return err
	}
	manager := wg.manager
	wg.mu.Unlock()

	log.Println("dynamically reconfiguring wireguard interface")
	wg.emitInfoLogf("dynamically reconfiguring wireguard interface")

	config := wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &listenPort,
		Peers:        peerConfigs,
		ReplacePeers: true,
	}

	if err := manager.ApplyConfig(config); err != nil {
		return fmt.Errorf("failed to reconfigure interface during restart: %w", err)
	}

	log.Println("wireguard interface reconfigured successfully without downtime")
	wg.emitInfoLogf("wireguard interface reconfigured successfully without downtime")
	return nil
}

// Shutdown stops the WireGuard backend
func (wg *WireGuard) Shutdown() {

	wg.shutdownOnce.Do(func() {
		wg.mu.Lock()
		defer wg.mu.Unlock()

		wg.shutdownLocked()
	})
}

func buildPeerConfigsForRestart(peers []*PeerInfo, presharedKey *wgtypes.Key) ([]wgtypes.PeerConfig, error) {
	orderedPeers := append([]*PeerInfo(nil), peers...)
	sort.Slice(orderedPeers, func(i, j int) bool {
		return orderedPeers[i].PublicKey.String() < orderedPeers[j].PublicKey.String()
	})

	peerConfigs := make([]wgtypes.PeerConfig, 0, len(orderedPeers))
	for _, peer := range orderedPeers {
		if len(peer.AllowedIPs) == 0 {
			return nil, fmt.Errorf("peer %s has no allowed IPs", peer.Email)
		}

		peerConfigs = append(peerConfigs, buildAddConfig(peer.PublicKey, peer.AllowedIPs, presharedKey))
	}

	return peerConfigs, nil
}

func (wg *WireGuard) shutdownLocked() {
	if wg.cancelFunc != nil {
		wg.cancelFunc()
	}

	// Stop tickers
	if wg.updateTicker != nil {
		wg.updateTicker.Stop()
	}
	if wg.cleanupTicker != nil {
		wg.cleanupTicker.Stop()
	}

	if wg.hostRouting != nil {
		wg.hostRouting()
		wg.hostRouting = nil
	}

	if wg.manager != nil {
		if err := wg.manager.Close(); err != nil {
			log.Printf("error closing manager: %v", err)
			wg.emitLogLocked(logSeverityError, fmt.Sprintf("error closing manager: %v", err))
		}
		wg.manager = nil
	}

	wg.state = lifecycleStopped
	wg.version = ""
	wg.emitLogLocked(logSeverityInfo, "wireguard shutdown complete")
	if wg.logChan != nil {
		close(wg.logChan)
		wg.logChan = nil
	}

	log.Println("wireguard shutdown complete")
}
