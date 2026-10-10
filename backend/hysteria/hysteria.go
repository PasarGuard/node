package hysteria

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// statsStartupTimeout bounds how long New waits for the core's stats API.
// Hysteria binds every listener before the first packet arrives, so this only
// has to cover process start plus a QUIC handshake it does not perform — a
// second is generous, the timeout exists to turn a hung core into a start
// error rather than an infinite wait.
const statsStartupTimeout = 15 * time.Second

const statsStartupPollInterval = 200 * time.Millisecond

// Hysteria implements backend.Backend for the hysteria2 core.
//
// Design notes that are not obvious from the code:
//
//   - Per-user traffic, online counts and kick all come from hysteria's own
//     traffic stats API, not from an in-core patch. That is why there is no
//     budget/binary-exact enforcement here the way sing-box's quota endpoint
//     has one: stock hysteria counts and reports but does not enforce. Limit
//     enforcement is therefore the panel's job — adaptive polling plus an
//     immediate kick when the poll says the user is over (see UpdateUsers).
//   - A user change is a restart, because auth.userpass is a config block with
//     no runtime API. Same trade sing-box makes (backend/singbox/user.go:13-21).
//   - There is one traffic-stats listener per core, on that core's own apiPort.
//     The CONTRACT's apiPort+1 quota rule (CONTRACT §1.4) does not apply here:
//     there is no second endpoint to make room for.
type Hysteria struct {
	config  *Config
	cfg     *config.Config
	core    *Core
	handler *statsClient
	apiPort int
	users   []*common.User

	mu         sync.RWMutex
	syncMu     sync.Mutex
	restarting bool

	// idle is true when a userpass core holds zero eligible users: upstream
	// refuses to start such a config ("auth.userpass: empty auth userpass"),
	// so the child is deliberately not running. An idle backend still answers
	// RPCs (Started() reports true with uptime 0) — that is what keeps the
	// panel health check green and the node out of the Start-retry loop the
	// old behaviour caused. SyncUsers wakes it; an empty roster puts it back.
	idle bool

	// pendingStats holds per-user counters drained before a planned restart, so
	// traffic that flowed between the panel's last poll and the restart is not
	// lost with the core's memory. Same reason sing-box has one
	// (backend/singbox/stats.go:44) and the same consumption rule: only a
	// user-facing read with reset=true may clear it, or an Outbounds poll that
	// ticks first would drop the bytes on the floor.
	pendingStats map[string]int64
}

// New builds and starts one hysteria2 core instance.
func New(ctx context.Context, hyConfig *Config, users []*common.User, apiPort int, cfg *config.Config) (*Hysteria, error) {
	if hyConfig == nil {
		return nil, errors.New("hysteria config must not be nil")
	}
	if apiPort <= 0 {
		return nil, errors.New("hysteria requires an api port for its traffic stats listener")
	}

	executablePath, err := filepath.Abs(hysteriaExecutablePath(cfg))
	if err != nil {
		return nil, err
	}
	configAbsolutePath, err := filepath.Abs(cfg.GeneratedConfigPath)
	if err != nil {
		return nil, err
	}

	secret, err := newTrafficStatsSecret()
	if err != nil {
		return nil, err
	}

	// The core has no health loop of its own: its health is the reachability of
	// the traffic stats API, which the panel's own stats poll already proves on
	// every tick, and CoreStatuses reports the process state (CONTRACT §3.4).
	// One extra poller would only duplicate that work.
	h := &Hysteria{
		cfg:          cfg,
		apiPort:      apiPort,
		pendingStats: map[string]int64{},
	}

	// The listener address is the node's own port, and the secret is generated
	// here rather than read from the operator's config, so a stored core config
	// can never leave the endpoint open with a known secret.
	hyConfig.EnableTrafficStats(apiPort, secret)

	if len(users) > 0 {
		log.Printf("syncing %d users on hysteria startup", len(users))
	} else {
		log.Println("no users provided on hysteria startup")
	}
	// A username upstream's decoder cannot accept fails here, before the child
	// is spawned, so the panel gets the offending identity by name instead of a
	// core that exited on a config-parse FATAL.
	if err := hyConfig.syncUsers(users); err != nil {
		return nil, err
	}

	h.config = hyConfig

	core, err := NewCore(executablePath, configAbsolutePath, cfg.LogBufferSize, cfg.StartupLogTailSize)
	if err != nil {
		return nil, err
	}
	h.core = core

	core.SetLogger(cfg.Debug)
	h.handler = newStatsClient(apiPort, secret)

	// A userpass core with an empty roster must not spawn the child: it would
	// FATAL on the config parse and the panel would restart it every health
	// tick (the crash-loop the round-2 E2E hit). Idle instead — the first
	// SyncUsers with a real user starts it.
	if hyConfig.needsUsers() && len(hyConfig.userNames()) == 0 {
		h.idle = true
		log.Println("hysteria core idle: no eligible users; will start on the first user sync")
		return h, nil
	}

	if err = core.Start(hyConfig); err != nil {
		return nil, err
	}

	if err = h.checkStatus(ctx); err != nil {
		h.Shutdown()
		return nil, err
	}
	core.SwitchToRuntimeLogPhase()

	log.Println("hysteria started, Version:", h.Version())
	return h, nil
}

// needsUsers reports whether this auth mode can only run with an injected
// userpass map. password/http/command carry their own credentials and are
// unaffected by the panel's user roster.
func (c *Config) needsUsers() bool {
	switch c.AuthType() {
	case "password", "http", "command":
		return false
	default: // userpass (and anything the panel validated into it)
		return true
	}
}

func (h *Hysteria) isIdle() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.idle
}

func (h *Hysteria) setIdle(v bool) {
	h.mu.Lock()
	h.idle = v
	h.mu.Unlock()
}

// newTrafficStatsSecret returns a fresh 32-byte hex secret. crypto/rand, not
// math/rand: this value authorises an endpoint that can read and zero every
// user's traffic counters.
func newTrafficStatsSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("could not generate a traffic stats secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func (h *Hysteria) Logs() <-chan string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.core.Logs()
}

func (h *Hysteria) Version() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.core.Version()
}

func (h *Hysteria) Started() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	// Idle is a deliberate not-running, not a crash: reporting false would make
	// GetBackendStats fail the panel health check forever and re-arm the
	// Start-retry loop this state exists to prevent. Uptime reads 0.
	if h.idle {
		return true
	}
	return h.core.Started()
}

func (h *Hysteria) Restart() error {
	if h.isIdle() {
		// Nothing to restart: the child is intentionally not running and the
		// current config has no user to start for.
		return nil
	}
	return h.restartCoreWithConfig(h.getConfig().Clone())
}

// restartCoreWithConfig restarts the child with a new config.
//
// One lock for the whole operation, and the restarting flag is cleared before
// the lock is released. The obvious two-lock version deadlocks: Go runs defers
// LIFO, so the deferred Unlock queued first runs LAST, and the deferred
// Lock that clears the flag then waits on a mutex this function still holds.
func (h *Hysteria) restartCoreWithConfig(config *Config) error {
	h.mu.Lock()
	if h.restarting {
		h.mu.Unlock()
		return errors.New("hysteria is already restarting")
	}
	h.restarting = true
	err := h.core.Restart(config)
	h.restarting = false
	h.mu.Unlock()
	return err
}

func (h *Hysteria) getConfig() *Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.config
}

func (h *Hysteria) setConfig(config *Config) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config = config
}

func (h *Hysteria) Shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.core != nil {
		h.core.Stop()
		h.core = nil
	}
}

// checkStatus blocks until the core's stats API answers, or gives up.
//
// Hysteria binds its stats listener in the same constructor as the QUIC
// listener (app/cmd/server.go:1498-1502), so a reachable stats API is proof the
// server accepted the config. Without this a bad `listen` port surfaces to the
// panel only as a core that never bills anyone.
func (h *Hysteria) checkStatus(ctx context.Context) error {
	deadline := time.Now().Add(statsStartupTimeout)
	ticker := time.NewTicker(statsStartupPollInterval)
	defer ticker.Stop()

	var lastErr error
	for {
		if !h.core.Started() {
			return fmt.Errorf("hysteria exited during startup: %s", h.startupFailureText())
		}
		if _, err := h.handler.online(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("hysteria traffic stats api never came up: %w (last: %s)", lastErr, h.startupFailureText())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (h *Hysteria) startupFailureText() string {
	if tail := h.core.StartupLogTail(5); len(tail) > 0 {
		return strings.Join(tail, " | ")
	}
	return "no output"
}
