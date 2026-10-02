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

	core, err := NewSingBoxCore(executableAbsolutePath, configAbsolutePath, cfg.LogBufferSize, cfg.StartupLogTailSize)
	if err != nil {
		return nil, err
	}

	if err = core.Start(sbConfig, cfg.Debug); err != nil {
		return nil, err
	}
	sb.core = core

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
