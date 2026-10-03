package singbox

import (
	"context"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// SingBox implements backend.Backend for the sing-box core.
type SingBox struct {
	config     *Config
	cfg        *config.Config
	core       *Core
	handler    *statsClient
	apiPort    int
	users      []*common.User
	cancelFunc context.CancelFunc
	mu         sync.RWMutex
	syncMu     sync.Mutex

	// debounced sync (SINGBOX_SYNC_DEBOUNCE_SECONDS): user changes update the
	// desired state immediately but materialize with one coalesced restart.
	// quota-exhaustion events for the panel; created lazily by QuotaEventCh.
	eventOnce   sync.Once
	QuotaEvents chan QuotaEvent

	// quotaEndpoint/secret address the core's control endpoint, used to detect
	// exhaustion promptly. Empty when the endpoint is not enabled.
	quotaEndpoint string
	quotaSecret   string
	// quotaPort is the loopback port the control endpoint is bound to.
	quotaPort int

	debounceTimer *time.Timer
	lastFlushAt   time.Time
	flushFailures int
	restartCount  int
	shuttingDown  bool
	pendingStats  map[string]int64 // counters flushed before a planned restart
}

// RestartCount reports how many planned core restarts the backend has done
// (used by tests to prove coalescing: N rapid changes -> 1 restart).
func (s *SingBox) RestartCount() int {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	return s.restartCount
}

func New(ctx context.Context, sbConfig *Config, users []*common.User, apiPort, metricPort int, cfg *config.Config) (*SingBox, error) {
	executableAbsolutePath, err := filepath.Abs(cfg.SingBoxExecutablePath)
	if err != nil {
		return nil, err
	}
	configAbsolutePath, err := filepath.Abs(cfg.GeneratedConfigPath)
	if err != nil {
		return nil, err
	}

	xCtx, xCancel := context.WithCancel(context.Background())

	sb := &SingBox{
		cancelFunc:   xCancel,
		cfg:          cfg,
		apiPort:      apiPort,
		pendingStats: map[string]int64{},
	}

	start := time.Now()

	if err = sbConfig.ApplyAPI(apiPort); err != nil {
		return nil, err
	}

	if len(users) > 0 {
		log.Printf("syncing %d users on startup", len(users))
		sbConfig.syncUsers(users)
	} else {
		log.Println("no users provided on startup")
	}

	sb.config = sbConfig
	log.Println("config generated in", time.Since(start).Seconds(), "second.")

	core, err := NewSingBoxCore(executableAbsolutePath, configAbsolutePath, cfg.LogBufferSize, cfg.StartupLogTailSize, cfg.SingBoxAllowNoV2RayAPI, cfg.QuotaSecret)
	if err != nil {
		return nil, err
	}

	// Turn the control endpoint on before the core starts, so the core owns it
	// from the first request rather than gaining it on a later sync. This is
	// what lets a live core receive an updated budget, and what lets the node
	// notice a budget has run out — without it the panel only learns on its
	// next usage poll.
	if core.HasQuotaPatch() {
		sbConfig.EnableQuotaEndpoint(core.QuotaEndpointPort(apiPort), "")
	}

	if err = core.Start(sbConfig, cfg.Debug); err != nil {
		return nil, err
	}
	sb.core = core

	if endpoint := sbConfig.quotaEndpoint(); endpoint != "" {
		sb.mu.Lock()
		sb.quotaEndpoint = endpoint
		sb.quotaSecret = cfg.QuotaSecret
		sb.mu.Unlock()
		log.Printf("quota monitor starting against %s", endpoint)
		sb.startQuotaMonitor(xCtx, endpoint, cfg.QuotaSecret)
	} else {
		log.Printf("no quota endpoint configured; quota monitor not started")
	}

	handler, err := newStatsClient(apiPort)
	if err != nil {
		sb.Shutdown()
		return nil, err
	}
	sb.handler = handler

	if err = sb.checkSingBoxStatus(ctx); err != nil {
		sb.Shutdown()
		return nil, err
	}

	go sb.checkSingBoxHealth(xCtx)

	log.Println("sing-box started, Version:", sb.Version())

	return sb, nil
}

func (s *SingBox) Logs() <-chan string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.core.Logs()
}

func (s *SingBox) Version() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.core.Version()
}

func (s *SingBox) Started() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.core.Started()
}

func (s *SingBox) Restart() error {
	return s.restartCoreWithConfig(s.getConfig())
}

// RestartFailClosed revives the core after it died on its own, zeroing every
// budget first.
//
// Restart() reuses the in-memory config, which holds "remaining as of the last
// panel sync" — already spent by the core that just died. Reusing it would give
// the user a second budget for the same traffic (KNOWN-ISSUES #15), so the
// revived core starts with every budget at zero and moves nothing until the
// panel re-syncs with a freshly computed remaining.
//
// Contrast with flushLocked (a panel-driven user change): there the restart is
// *driven by* a sync, so the config is current by construction and the
// counters are drained first. This path has no sync behind it, which is
// exactly why it must fail closed.
func (s *SingBox) RestartFailClosed() (reset int, err error) {
	s.syncMu.Lock()
	s.pendingStats = map[string]int64{} // the crashed core's last drain is not trustworthy
	s.syncMu.Unlock()

	candidate := s.getConfig().Clone()
	reset = candidate.resetQuotas()
	if reset > 0 {
		log.Printf("fail-closed restart: zeroing %d budget(s) until the panel re-syncs", reset)
	}
	return reset, s.restartCoreWithConfig(candidate)
}

func (s *SingBox) restartCoreWithConfig(config *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core.Restart(config, s.cfg.Debug)
}

func (s *SingBox) getConfig() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func (s *SingBox) setConfig(config *Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = config
}

func (s *SingBox) Shutdown() {
	s.syncMu.Lock()
	s.shuttingDown = true
	if s.debounceTimer != nil {
		s.debounceTimer.Stop()
		s.debounceTimer = nil
	}
	s.syncMu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancelFunc != nil {
		s.cancelFunc()
		s.cancelFunc = nil
	}
	if s.handler != nil {
		_ = s.handler.Close()
		s.handler = nil
	}
	if s.core != nil {
		s.core.Stop()
		s.core = nil
	}
}
