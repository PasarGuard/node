package xray

import (
	"context"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

type Xray struct {
	config     *Config
	cfg        *config.Config
	core       *Core
	handler    *api.XrayHandler
	metricPort int
	cancelFunc context.CancelFunc
	mu         sync.RWMutex
}

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

func (x *Xray) Logs() <-chan string {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.core.Logs()
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

func (x *Xray) Restart() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.core.Restart(x.config, x.cfg.Debug); err != nil {
		return err
	}
	return nil
}

func (x *Xray) Shutdown() {
	x.mu.Lock()
	defer x.mu.Unlock()

	// Cancel context first to stop health checks and other goroutines
	x.cancelFunc()

	// Stop core (this now waits for process termination)
	if x.core != nil {
		x.core.Stop()
	}

	// Close API handler
	if x.handler != nil {
		x.handler.Close()
	}

	// Shutdown is now complete - all resources are cleaned up
}
