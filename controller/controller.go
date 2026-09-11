package controller

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/backend/wireguard"
	"github.com/pasarguard/node/backend/xray"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
	"github.com/pasarguard/node/pkg/sysstats"
)

const NodeVersion = "0.5.4"

// keepAliveGrace is added to the configured keep-alive so a panel whose
// health interval equals keep_alive does not trip the watchdog on jitter.
const keepAliveGrace = 5 * time.Second

type Service interface {
	Disconnect()
}

type Controller struct {
	backend     backend.Backend
	cfg         *config.Config
	apiPort     int
	metricPort  int
	lastRequest time.Time
	stats       *common.SystemStatsResponse
	cancelFunc  context.CancelFunc
	mu          sync.RWMutex
	controlMu   sync.Mutex
}

func New(cfg *config.Config) *Controller {
	_, cancel := context.WithCancel(context.Background())
	return &Controller{
		cfg:        cfg,
		apiPort:    netutil.FindFreePort(),
		metricPort: netutil.FindFreePort(),
		cancelFunc: cancel,
	}
}

func (c *Controller) ApiKey() uuid.UUID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.ApiKey
}

func (c *Controller) Connect(keepAlive uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRequest = time.Now()

	if c.cancelFunc != nil {
		c.cancelFunc()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancelFunc = cancel
	go c.recordSystemStats(ctx)
	if keepAlive > 0 {
		go c.keepAliveTracker(ctx, time.Duration(keepAlive)*time.Second)
	}
}

func (c *Controller) Disconnect() {
	c.mu.Lock()
	if c.cancelFunc != nil {
		c.cancelFunc()
		c.cancelFunc = nil
	}
	backend := c.backend
	c.backend = nil
	c.mu.Unlock()

	// Shutdown backend outside of lock to avoid deadlock
	// Shutdown() will wait for process termination to complete
	if backend != nil {
		backend.Shutdown()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.apiPort = netutil.FindFreePort()
	c.metricPort = netutil.FindFreePort()
}

func (c *Controller) LockControl() {
	c.controlMu.Lock()
}

func (c *Controller) UnlockControl() {
	c.controlMu.Unlock()
}

func (c *Controller) NewRequest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRequest = time.Now()
}

// StartOrAttach starts the core, or refreshes keep-alive if it is already running.
// Caller must hold LockControl. A second Start from another panel worker must not
// tear down a core that just finished starting.
func (c *Controller) StartOrAttach(ctx context.Context, data *common.Backend) error {
	if back := c.Backend(); back != nil && back.Started() {
		c.Connect(data.GetKeepAlive())
		return nil
	}
	if c.Backend() != nil {
		log.Println("Replacing a backend that is no longer running")
		c.Disconnect()
	}
	if err := c.StartBackend(ctx, data); err != nil {
		return err
	}
	c.Connect(data.GetKeepAlive())
	return nil
}

func (c *Controller) StartBackend(ctx context.Context, backend *common.Backend) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch backend.GetType() {
	case common.BackendType_XRAY:
		config, err := xray.NewConfig(backend.GetConfig(), backend.GetExcludeInbounds())
		if err != nil {
			return err
		}

		newBackend, err := xray.New(
			ctx,
			config,
			backend.GetUsers(),
			c.apiPort,
			c.metricPort,
			c.cfg,
		)
		if err != nil {
			return err
		}
		c.backend = newBackend

	case common.BackendType_WIREGUARD:
		config, err := wireguard.NewConfig(backend.GetConfig())
		if err != nil {
			return err
		}
		newBackend, err := wireguard.New(c.cfg, config, backend.GetUsers())
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

func keepAliveStale(lastRequest time.Time, keepAlive time.Duration, now time.Time) bool {
	return now.Sub(lastRequest) >= keepAlive+keepAliveGrace
}

func (c *Controller) keepAliveTracker(ctx context.Context, keepAlive time.Duration) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			stale := keepAliveStale(c.lastRequest, keepAlive, time.Now())
			c.mu.RUnlock()
			if !stale {
				continue
			}

			// Serialize with Start/Stop so a late watchdog cannot kill a core
			// that StartBackend just created.
			c.LockControl()
			c.mu.RLock()
			stale = keepAliveStale(c.lastRequest, keepAlive, time.Now())
			c.mu.RUnlock()
			if stale {
				log.Println("disconnect automatically due to keep alive timeout")
				c.Disconnect()
			}
			c.UnlockControl()
		}
	}
}

func (c *Controller) recordSystemStats(ctx context.Context) {
	interval := 1500 * time.Millisecond

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	collect := func() {
		stats, err := sysstats.GetSystemStats(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Failed to get system stats: %v", err)
			return
		}

		c.mu.Lock()
		c.stats = stats
		c.mu.Unlock()
	}

	collect()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collect()
		}
	}
}

func (c *Controller) SystemStats(ctx context.Context) *common.SystemStatsResponse {
	c.mu.RLock()
	statsSnapshot := c.stats
	backendSnapshot := c.backend
	c.mu.RUnlock()

	response := &common.SystemStatsResponse{}
	if statsSnapshot != nil {
		response = &common.SystemStatsResponse{
			MemTotal:               statsSnapshot.GetMemTotal(),
			MemUsed:                statsSnapshot.GetMemUsed(),
			CpuCores:               statsSnapshot.GetCpuCores(),
			CpuUsage:               statsSnapshot.GetCpuUsage(),
			IncomingBandwidthSpeed: statsSnapshot.GetIncomingBandwidthSpeed(),
			OutgoingBandwidthSpeed: statsSnapshot.GetOutgoingBandwidthSpeed(),
			Uptime:                 statsSnapshot.GetUptime(),
		}
	}

	if backendSnapshot == nil {
		return response
	}

	// Backend uptime is owned by each backend implementation; controller only forwards it here.
	backendStats, err := backendSnapshot.GetSysStats(ctx)
	if err != nil {
		log.Printf("Failed to get backend uptime for system stats: %v", err)
		return response
	}

	response.Uptime = uint64(backendStats.GetUptime())
	return response
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

func (c *Controller) OutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	c.mu.RLock()
	backendSnapshot := c.backend
	c.mu.RUnlock()

	if backendSnapshot == nil {
		return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
	}

	return backendSnapshot.GetOutboundsLatency(ctx, request)
}
