package controller

import (
	"context"
	"errors"
	"fmt"
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
	backend              backend.Backend
	cfg                  *config.Config
	apiPort              int
	metricPort           int
	clientIP             string
	lastRequest          time.Time
	connectionGeneration uint64
	stats                *common.SystemStatsResponse
	cancelFunc           context.CancelFunc
	mu                   sync.RWMutex
	controlMu            sync.Mutex
	userSyncMu           sync.Mutex
	maxUserSyncEpoch     uint64
}

// UserSyncEpochError reports a user mutation that is older than one already
// accepted by this node. Epoch zero remains available to legacy clients only
// until the first epoch-aware mutation is accepted.
type UserSyncEpochError struct {
	Received uint64
	Current  uint64
}

// UserSyncEpochBatch validates that every item in one streamed mutation uses
// the same epoch before any backend state is changed.
type UserSyncEpochBatch struct {
	epoch uint64
	set   bool
}

func (b *UserSyncEpochBatch) Add(epoch uint64) error {
	if !b.set {
		b.epoch = epoch
		b.set = true
		return nil
	}
	if epoch != b.epoch {
		return errors.New("all items must use the same user sync epoch")
	}
	return nil
}

func (b *UserSyncEpochBatch) Epoch() uint64 {
	return b.epoch
}

func (e *UserSyncEpochError) Error() string {
	return fmt.Sprintf("stale user sync epoch %d; current epoch is %d", e.Received, e.Current)
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

func (c *Controller) Connect(ip string, keepAlive uint64) {
	c.mu.Lock()
	c.lastRequest = time.Now()
	c.clientIP = ip
	c.connectionGeneration++
	generation := c.connectionGeneration

	if c.cancelFunc != nil {
		c.cancelFunc()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancelFunc = cancel
	c.mu.Unlock()

	go c.recordSystemStats(ctx)
	if keepAlive > 0 {
		go c.keepAliveTracker(ctx, time.Duration(keepAlive)*time.Second, generation)
	}
}

// Disconnect serializes an automatic or external disconnect with Start.
func (c *Controller) Disconnect() {
	c.LockControl()
	defer c.UnlockControl()
	c.DisconnectControlled()
}

// DisconnectControlled detaches the current backend before stopping it. The
// caller must hold the controller control lock, which makes replacement and
// keep-alive disconnects mutually exclusive.
func (c *Controller) DisconnectControlled() {
	c.mu.Lock()
	cancel := c.cancelFunc
	backend := c.backend
	c.backend = nil
	c.connectionGeneration++
	c.apiPort = netutil.FindFreePort()
	c.metricPort = netutil.FindFreePort()
	c.clientIP = ""
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	// Shutdown may wait for process termination; the detached backend can no
	// longer erase a backend that a later Start creates.
	if backend != nil {
		backend.Shutdown()
	}
}

func (c *Controller) Ip() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientIP
}

func (c *Controller) IsCurrentClient(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.clientIP == "" || c.clientIP == ip
}

func (c *Controller) LockControl() {
	c.controlMu.Lock()
}

func (c *Controller) UnlockControl() {
	c.controlMu.Unlock()
}

// ApplyUserSyncEpoch serializes every backend user mutation in epoch order.
// Advancing maxUserSyncEpoch happens before mutation so a failed higher-epoch
// request still fences all older in-flight or retried work.
func (c *Controller) ApplyUserSyncEpoch(epoch uint64, mutate func() error) error {
	c.userSyncMu.Lock()
	defer c.userSyncMu.Unlock()

	if epoch < c.maxUserSyncEpoch || (epoch == 0 && c.maxUserSyncEpoch > 0) {
		return &UserSyncEpochError{Received: epoch, Current: c.maxUserSyncEpoch}
	}
	if epoch > c.maxUserSyncEpoch {
		c.maxUserSyncEpoch = epoch
	}

	return mutate()
}

func (c *Controller) UserSyncEpoch() uint64 {
	c.userSyncMu.Lock()
	defer c.userSyncMu.Unlock()
	return c.maxUserSyncEpoch
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
		c.Connect(c.Ip(), data.GetKeepAlive())
		return nil
	}
	if c.Backend() != nil {
		log.Println("Replacing a backend that is no longer running")
		c.DisconnectControlled()
	}
	if err := c.StartBackend(ctx, data); err != nil {
		return err
	}
	c.Connect("", data.GetKeepAlive())
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

// StartBackendControlled replaces the current backend only after reserving the
// request epoch. The caller must hold the control lock and verify ownership.
func (c *Controller) StartBackendControlled(ctx context.Context, data *common.Backend, clientIP string) error {
	return c.ApplyUserSyncEpoch(data.GetUserSyncEpoch(), func() error {
		if back := c.Backend(); back != nil && back.Started() {
			c.Connect(clientIP, data.GetKeepAlive())
			return nil
		}
		if c.Backend() != nil {
			log.Println("Replacing a backend that is no longer running")
			c.DisconnectControlled()
		}

		if err := c.StartBackend(ctx, data); err != nil {
			return err
		}
		c.Connect(clientIP, data.GetKeepAlive())
		return nil
	})
}

func (c *Controller) Backend() backend.Backend {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.backend
}

func (c *Controller) keepAliveTracker(ctx context.Context, keepAlive time.Duration, generation uint64) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.keepAliveExpired(generation, keepAlive) {
				log.Println("disconnect automatically due to keep alive timeout")
				c.LockControl()
				if c.keepAliveExpired(generation, keepAlive) {
					c.DisconnectControlled()
				}
				c.UnlockControl()
			}
		}
	}
}

// keepAliveExpired verifies that the tracker still owns the current connection.
// A previous tracker may already have observed its timeout while Start is replacing
// the backend, so it must re-check its generation under the control lock before
// disconnecting anything.
func (c *Controller) keepAliveExpired(generation uint64, keepAlive time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connectionGeneration == generation && keepAliveStale(c.lastRequest, keepAlive, time.Now())
}

func keepAliveStale(lastRequest time.Time, keepAlive time.Duration, now time.Time) bool {
	return now.Sub(lastRequest) >= keepAlive+keepAliveGrace
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
	userSyncEpoch := c.UserSyncEpoch()

	c.mu.Lock()
	defer c.mu.Unlock()

	response := &common.BaseInfoResponse{
		Started:                false,
		CoreVersion:            "",
		NodeVersion:            NodeVersion,
		UserSyncEpochSupported: true,
		UserSyncEpoch:          userSyncEpoch,
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
