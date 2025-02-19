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

const NodeVersion = "0.1.2"

type Service interface {
	StopService()
}

type Controller struct {
	backend    backend.Backend
	sessionID  uuid.UUID
	apiPort    int
	stats      *common.SystemStatsResponse
	cancelFunc context.CancelFunc
	mu         sync.Mutex
}

func NewController() *Controller {
	c := &Controller{
		sessionID: uuid.Nil,
		apiPort:   tools.FindFreePort(),
	}
	c.startJobs()
	return c
}

func (c *Controller) GetSessionID() uuid.UUID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionID
}

func (c *Controller) Connect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionID = uuid.New()
}

func (c *Controller) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.backend != nil {
		c.backend.Shutdown()
	}
	c.backend = nil

	apiPort := tools.FindFreePort()
	c.apiPort = apiPort

	c.sessionID = uuid.Nil
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

func (c *Controller) GetBackend() backend.Backend {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backend
}

func (c *Controller) recordSystemStats(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			break
		default:
			stats, err := tools.GetSystemStats()
			if err != nil {
				log.Printf("Failed to get system stats: %v", err)
			} else {
				c.mu.Lock()
				c.stats = stats
				c.mu.Unlock()
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (c *Controller) GetStats() *common.SystemStatsResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

func (c *Controller) BaseInfoResponse(includeID bool, extra string) *common.BaseInfoResponse {
	c.mu.Lock()
	defer c.mu.Unlock()

	response := &common.BaseInfoResponse{
		Started:     false,
		CoreVersion: "",
		NodeVersion: NodeVersion,
		Extra:       extra,
	}

	if c.backend != nil {
		response.Started = c.backend.Started()
		response.CoreVersion = c.backend.GetVersion()
	}
	if includeID {
		response.SessionId = c.sessionID.String()
	}

	return response
}

func (c *Controller) startJobs() {
	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cancelFunc = cancel
	go c.recordSystemStats(ctx)
}

func (c *Controller) StopJobs() {
	c.mu.Lock()
	c.cancelFunc()
	c.mu.Unlock()

	c.Disconnect()

}
