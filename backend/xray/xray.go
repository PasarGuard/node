package xray

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/m03ed/gozargah-node/backend"
	"github.com/m03ed/gozargah-node/backend/xray/api"
	"github.com/m03ed/gozargah-node/common"
)

type Xray struct {
	config     *Config
	core       *Core
	handler    *api.XrayHandler
	cancelFunc context.CancelFunc
	mu         sync.RWMutex
}

func NewXray(ctx context.Context, port int, executablePath, assetsPath, configPath string) (*Xray, error) {
	executableAbsolutePath, err := filepath.Abs(executablePath)
	if err != nil {
		return nil, err
	}

	assetsAbsolutePath, err := filepath.Abs(assetsPath)
	if err != nil {
		return nil, err
	}

	configAbsolutePath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}

	xCtx, xCancel := context.WithCancel(context.Background())

	xray := &Xray{cancelFunc: xCancel}

	start := time.Now()

	config, ok := ctx.Value(backend.ConfigKey{}).(*Config)
	if !ok {
		return nil, errors.New("xray config has not been initialized")
	}

	if err = config.ApplyAPI(port); err != nil {
		return nil, err
	}

	users := ctx.Value(backend.UsersKey{}).([]*common.User)
	config.syncUsers(users)

	xray.config = config

	log.Println("config generated in", time.Since(start).Seconds(), "second.")

	core, err := NewXRayCore(executableAbsolutePath, assetsAbsolutePath, configAbsolutePath)
	if err != nil {
		return nil, err
	}

	if err = core.Start(config); err != nil {
		return nil, err
	}

	xray.core = core

	if err = xray.checkXrayStatus(); err != nil {
		xray.Shutdown()
		return nil, err
	}

	handler, err := api.NewXrayAPI(port)
	if err != nil {
		xray.Shutdown()
		return nil, err
	}
	xray.handler = handler
	go xray.checkXrayHealth(xCtx)

	return xray, nil
}

func (x *Xray) Logs() chan string {
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
	return x.core.Started()
}

func (x *Xray) Restart() error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.core.Restart(x.config); err != nil {
		return err
	}
	return nil
}

func (x *Xray) Shutdown() {
	x.mu.Lock()
	defer x.mu.Unlock()

	x.cancelFunc()

	if x.core != nil {
		x.core.Stop()
	}
	if x.handler != nil {
		x.handler.Close()
	}
}
