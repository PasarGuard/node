package xray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// Lock order: syncMu, then mu, then core.mu. syncMu serializes user syncs and
// restarts; Shutdown takes only mu, so it never waits for a sync.
type Xray struct {
	config     *Config
	cfg        *config.Config
	core       *Core
	handler    *api.XrayHandler
	apiPort    int
	metricPort int
	cancelFunc context.CancelFunc
	mu         sync.RWMutex
	syncMu     sync.Mutex
	closed     bool // set by Shutdown under mu
}

var errXrayShutdown = errors.New("xray backend is shut down")

// restartReadyTimeout bounds how long a restart holds syncMu waiting for the
// new core's API.
const restartReadyTimeout = 30 * time.Second

// fullSyncReadyTimeout bounds how long applyConfigWithRestart waits for the
// restarted core's API, for both a full user sync (SyncUsers) and
// UpdateUsersAndRestart. The wait does not follow the caller's cancellation,
// so it is sized for a large user list, like the controller's start timeout.
const fullSyncReadyTimeout = 3 * time.Minute

func New(ctx context.Context, xrayConfig *Config, users []*common.User, apiPort, metricPort int, cfg *config.Config) (*Xray, error) {
	executableAbsolutePath, err := filepath.Abs(cfg.XrayExecutablePath)
	if err != nil {
		return nil, err
	}

	assetsAbsolutePath, err := filepath.Abs(cfg.XrayAssetsPath)
	if err != nil {
		return nil, err
	}

	configAbsolutePath, err := filepath.Abs(cfg.GeneratedConfigPath)
	if err != nil {
		return nil, err
	}

	xCtx, xCancel := context.WithCancel(context.Background())

	xray := &Xray{
		cancelFunc: xCancel,
		cfg:        cfg,
		apiPort:    apiPort,
		metricPort: metricPort,
	}

	start := time.Now()

	if err = xrayConfig.ApplyAPI(apiPort, metricPort); err != nil {
		return nil, err
	}

	if len(users) > 0 {
		log.Printf("syncing %d users on startup", len(users))
		xrayConfig.syncUsers(users)
		// Verify users were synced by counting clients in all inbounds
		totalClients := 0
		for _, inbound := range xrayConfig.InboundConfigs {
			if !inbound.exclude && inbound.clients != nil {
				totalClients += len(inbound.clients)
			}
		}
		log.Printf("synced %d users on startup, total clients in config: %d", len(users), totalClients)
	} else {
		log.Println("no users provided on startup")
	}

	xray.config = xrayConfig

	log.Println("config generated in", time.Since(start).Seconds(), "second.")

	core, err := NewXRayCore(executableAbsolutePath, assetsAbsolutePath, configAbsolutePath, cfg.LogBufferSize, cfg.StartupLogTailSize)
	if err != nil {
		return nil, err
	}

	if err = core.Start(xrayConfig, cfg.Debug); err != nil {
		return nil, err
	}

	xray.core = core

	handler, err := api.NewXrayAPI(apiPort)
	if err != nil {
		xray.Shutdown()
		return nil, err
	}
	xray.handler = handler

	if err = xray.checkXrayStatus(ctx); err != nil {
		xray.Shutdown()
		return nil, err
	}

	// Wait a bit for Xray to fully initialize before starting health checks
	// This prevents false positives during startup
	go xray.checkXrayHealth(xCtx)

	log.Println("xray started, Version:", xray.Version())

	return xray, nil
}

func (x *Xray) SubscribeLogs(ctx context.Context) <-chan string {
	x.mu.RLock()
	core := x.core
	x.mu.RUnlock()

	if core == nil {
		ch := make(chan string)
		close(ch)
		return ch
	}

	return core.SubscribeLogs(ctx)
}

func (x *Xray) Version() string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.core.Version()
}

func (x *Xray) Started() bool {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.core.Started()
}

// Restart restarts the core from the current config and waits until its API
// answers.
func (x *Xray) Restart() error {
	x.syncMu.Lock()
	defer x.syncMu.Unlock()

	return x.restartLocked(context.Background())
}

// restartLocked restarts the core from x.config and waits until its API
// answers. The caller holds syncMu for the whole restart, so a user sync sent
// meanwhile waits for the new core. Against a core that is still booting, a
// removal fails, while the new core, built from x.config before the removal,
// keeps the user.
func (x *Xray) restartLocked(ctx context.Context) error {
	if err := x.restartCoreWithConfig(x.config); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, restartReadyTimeout)
	defer cancel()
	if err := x.checkXrayStatus(ctx); err != nil {
		return fmt.Errorf("xray API not ready within %s after restart: %w", restartReadyTimeout, err)
	}
	return nil
}

func (x *Xray) restartCoreWithConfig(config *Config) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	// Shutdown sets closed under mu, so a restart that waited for mu (a full-sync
	// rollback, a health restart) cannot start a core after Shutdown returned.
	if x.closed {
		return errXrayShutdown
	}
	if err := x.core.Restart(config, x.cfg.Debug); err != nil {
		return err
	}
	return nil
}

func (x *Xray) setConfig(config *Config) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.config = config
}

func (x *Xray) Shutdown() {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.closed = true

	// Cancel context first to stop health checks and other goroutines
	x.cancelFunc()

	// Stop core (this now waits for process termination)
	if x.core != nil {
		x.core.Stop()
		x.core.CloseLogs()
	}

	// Close API handler
	if x.handler != nil {
		x.handler.Close()
	}

	// Shutdown is now complete - all resources are cleaned up
}
