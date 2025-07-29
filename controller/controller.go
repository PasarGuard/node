package controller

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/m03ed/gozargah-node/backend"
	"github.com/m03ed/gozargah-node/backend/xray"
	"github.com/m03ed/gozargah-node/common"
	"github.com/m03ed/gozargah-node/config"
	"github.com/m03ed/gozargah-node/tools"
)

const NodeVersion = "0.0.12"

type Service interface {
	Disconnect()
}

type Controller struct {
	backend     backend.Backend
	apiKey      uuid.UUID
	apiPort     int
	clientIP    string
	lastRequest time.Time
	stats       *common.SystemStatsResponse
	cancelFunc  context.CancelFunc
	mu          sync.RWMutex
}

func New() *Controller {
	_, cancel := context.WithCancel(context.Background())
	return &Controller{
		apiKey:     config.ApiKey,
		apiPort:    tools.FindFreePort(),
		cancelFunc: cancel,
	}
}

func (c *Controller) ApiKey() uuid.UUID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiKey
}

func (c *Controller) Connect(ip string, keepAlive uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRequest = time.Now()
	c.clientIP = ip

	ctx, cancel := context.WithCancel(context.Background())
	c.cancelFunc = cancel
	go c.recordSystemStats(ctx)
	if keepAlive > 0 {
		go c.keepAliveTracker(ctx, time.Duration(keepAlive)*time.Second)
	}
}

func (c *Controller) Disconnect() {
	c.cancelFunc()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.backend != nil {
		c.backend.Shutdown()
	}
	c.backend = nil
	c.apiPort = tools.FindFreePort()
	c.clientIP = ""
}

func (c *Controller) Ip() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientIP
}

func (c *Controller) NewRequest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRequest = time.Now()
}

func (c *Controller) StartBackend(ctx context.Context, backendType common.BackendType) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch backendType {
	case common.BackendType_XRAY:
		newBackend, err := xray.NewXray(ctx, c.apiPort, config.XrayExecutablePath, config.XrayAssetsPath, config.GeneratedConfigPath)
		if err != nil {
			return err
		}
		c.backend = newBackend
	default:
		return errors.New("invalid backend type")
	}

	return nil
}

func (c *Controller) Backend() backend.Backend {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.backend
}

func (c *Controller) keepAliveTracker(ctx context.Context, keepAlive time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			c.mu.RLock()
			lastRequest := c.lastRequest
			c.mu.RUnlock()
			if time.Since(lastRequest) >= keepAlive {
				log.Println("disconnect automatically due to keep alive timeout")
				c.Disconnect()
			}
			time.Sleep(5 * time.Second)
		}
	}
}

func (c *Controller) recordSystemStats(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			stats, err := tools.GetSystemStats()
			if err != nil {
				log.Printf("Failed to get system stats: %v", err)
			} else {
				c.mu.Lock()
				c.stats = stats
				c.mu.Unlock()
			}
		}
	}
}

func (c *Controller) SystemStats() *common.SystemStatsResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

func (c *Controller) BaseInfoResponse() *common.BaseInfoResponse {
	c.mu.Lock()
	defer c.mu.Unlock()

	response := &common.BaseInfoResponse{
		Started:     false,
		CoreVersion: "",
		NodeVersion: NodeVersion,
	}

	if c.backend != nil {
		response.Started = c.backend.Started()
		response.CoreVersion = c.backend.Version()
	}

	return response
}
