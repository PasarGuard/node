package mtproto

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
)

// telemtStartupTimeout bounds the wait for telemt's API after a start. telemt
// binds its API and metrics only after the STUN probe and the Telegram DC
// connectivity check, which took 19-58 s in tests with slow or unreachable
// DCs. It is a variable so tests can lower it.
var telemtStartupTimeout = 90 * time.Second

const (
	// telemtReadyTimeout is how long the background readiness watcher waits
	// for /v1/health/ready before it warns. Not being ready (no reachable
	// Telegram upstream yet) is only logged: Telegram egress problems must
	// not fail or delay a start.
	telemtReadyTimeout = 30 * time.Second
	// readyRecheckInterval is how often the watcher checks again after the
	// warning, to log when telemt becomes ready.
	readyRecheckInterval = 10 * time.Second
	// telemtStartupTailSize is how many lines of telemt output are kept for a
	// startup error.
	telemtStartupTailSize = 50
	// telemtCrashTailSize is how many of those lines are logged after a crash.
	telemtCrashTailSize = 10

	supervisorInitialBackoff = time.Second
	supervisorMaxBackoff     = 60 * time.Second

	internalPortAttempts = 32
	healthPollInterval   = 250 * time.Millisecond
	readyPollInterval    = 500 * time.Millisecond
)

var errClosed = errors.New("mtproto backend is shut down")

func New(ctx context.Context, cfg *config.Config, mtConfig *Config, users []*common.User) (*MTProto, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	if mtConfig == nil {
		return nil, errors.New("mtproto config is nil")
	}

	apiPort, metricsPort, err := pickInternalPorts(mtConfig.ListenPorts(), netutil.FindFreePort)
	if err != nil {
		return nil, err
	}

	authHeader, err := generateBearerToken()
	if err != nil {
		return nil, err
	}
	telemtDir, err := prepareTelemtDir(cfg.GeneratedConfigPath)
	if err != nil {
		return nil, err
	}
	process, err := newProcessManager(cfg.TelemtExecutablePath, telemtDir, cfg.LogBufferSize, telemtStartupTailSize)
	if err != nil {
		return nil, err
	}

	activeUsers, _ := ActiveUsersFromCommon(users, mtConfig.InboundTag)

	lifetime, cancel := context.WithCancel(context.Background())
	mt := &MTProto{
		cfg:            cfg,
		config:         mtConfig,
		process:        process,
		configPath:     filepath.Join(telemtDir, "config.toml"),
		apiClient:      newAPIClient(fmt.Sprintf("http://127.0.0.1:%d", apiPort), authHeader),
		metricsScraper: newMetricsScraper(fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort)),
		tracker:        newTrafficTracker(),
		apiPort:        apiPort,
		metricsPort:    metricsPort,
		apiAuthHeader:  authHeader,
		desired:        cloneRuntimeUserMap(activeUsers),
		lifetime:       lifetime,
		cancel:         cancel,
	}

	// The panel's Start call has a short deadline (10 s by default) while
	// telemt may need far longer to bind its API. Let a slow start finish
	// anyway: the panel's retry then attaches to the running backend.
	startCtx, cancelStart := context.WithTimeout(context.WithoutCancel(ctx), telemtStartupTimeout)
	defer cancelStart()

	mt.syncMu.Lock()
	err = mt.writeRenderedConfigLocked(mt.desired)
	if err == nil {
		err = mt.startLocked(startCtx)
	}
	mt.syncMu.Unlock()
	if err != nil {
		mt.Shutdown()
		return nil, err
	}

	mt.background.Go(mt.supervise)
	return mt, nil
}

// Shutdown stops the supervisor and telemt, closes the log stream and removes
// the rendered config, which holds user secrets and the API token. Every
// mutating call afterwards returns errClosed.
func (m *MTProto) Shutdown() {
	m.cancel()

	m.syncMu.Lock()
	if !m.closed {
		m.closed = true
		m.process.Close()
		if err := os.Remove(m.configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: failed to remove the telemt config: %v", err)
		}
	}
	m.syncMu.Unlock()

	// The supervisor and readiness watchers end on the lifetime cancel. They
	// are only added under syncMu before closed is set, so no Add races this.
	m.background.Wait()
}

// prepareTelemtDir creates <generated>/telemt with owner-only permissions and
// returns it with symlinks resolved: telemt 3.5.8+ opens the config path one
// component at a time with O_NOFOLLOW, so a symlinked directory fails.
func prepareTelemtDir(generatedConfigPath string) (string, error) {
	root, err := filepath.Abs(generatedConfigPath)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "telemt")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("failed to create the telemt config directory: %w", err)
	}
	// MkdirAll keeps the mode of an existing directory.
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("failed to restrict the telemt config directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve the telemt config directory: %w", err)
	}
	return resolved, nil
}

// pickInternalPorts picks free ports for telemt's loopback API and metrics
// endpoints, distinct from each other and from the config's client ports.
func pickInternalPorts(listenPorts []int, findFreePort func() int) (apiPort, metricsPort int, err error) {
	pick := func(name string, taken ...int) (int, error) {
		for range internalPortAttempts {
			port := findFreePort()
			if port >= 1 && port <= 65535 && !slices.Contains(listenPorts, port) && !slices.Contains(taken, port) {
				return port, nil
			}
		}
		return 0, fmt.Errorf("failed to find a free telemt %s port outside the mtproto listen ports %v after %d attempts",
			name, listenPorts, internalPortAttempts)
	}

	if apiPort, err = pick("API"); err != nil {
		return 0, 0, err
	}
	if metricsPort, err = pick("metrics", apiPort); err != nil {
		return 0, 0, err
	}
	return apiPort, metricsPort, nil
}

// startLocked starts telemt on the rendered config and waits for its API.
// A failure stops telemt and carries its last output. Readiness is watched in
// the background. Requires syncMu.
func (m *MTProto) startLocked(ctx context.Context) error {
	if m.lifetime.Err() != nil {
		return errClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.process.Start(m.configPath); err != nil {
		return err
	}
	// Once telemt runs, only telemtStartupTimeout and Shutdown bound its
	// startup: a caller that gives up must not kill a telemt still binding.
	if err := m.waitForHealth(context.WithoutCancel(ctx)); err != nil {
		m.process.Stop()
		return m.startupError(err)
	}
	m.healthyAt = time.Now()

	// A new telemt has fresh user admission state: no API write is pending.
	m.apiSent = nil

	exited := m.process.Exited()
	m.background.Go(func() { m.watchReadiness(exited) })
	return nil
}

// watchReadiness logs whether a started telemt gets ready to serve clients:
// a warning after telemtReadyTimeout, then a line once it is ready. It stops
// when exited (that telemt's Exited channel) closes or on Shutdown.
func (m *MTProto) watchReadiness(exited <-chan struct{}) {
	ctx, cancel := context.WithCancel(m.lifetime)
	defer cancel()
	go func() {
		select {
		case <-exited:
			cancel()
		case <-ctx.Done():
		}
	}()

	err := m.waitForReady(ctx, telemtReadyTimeout)
	if err == nil || ctx.Err() != nil {
		return
	}
	log.Printf("warning: telemt is running but not ready to serve clients yet: %v", err)

	ticker := time.NewTicker(readyRecheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if m.apiClient.Ready(ctx) == nil {
			log.Println("telemt is now ready to serve clients")
			return
		}
	}
}

func (m *MTProto) startupError(err error) error {
	tail := m.process.StartupTail(telemtStartupTailSize)
	if len(tail) == 0 {
		return fmt.Errorf("failed to start telemt: %w", err)
	}
	return fmt.Errorf("failed to start telemt: %w; recent telemt output:\n%s", err, strings.Join(tail, "\n"))
}

// waitForHealth polls /v1/health until it answers, telemt exits, the backend
// shuts down, or telemtStartupTimeout passes.
func (m *MTProto) waitForHealth(ctx context.Context) error {
	timeout := telemtStartupTimeout
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	exited := m.process.Exited()
	ticker := time.NewTicker(healthPollInterval)
	defer ticker.Stop()

	for {
		if err := m.apiClient.Health(waitCtx); err == nil {
			return nil
		}

		select {
		case <-exited:
			return errors.New("telemt exited before its API became healthy")
		case <-m.lifetime.Done():
			return errClosed
		case <-waitCtx.Done():
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("stopped waiting for the telemt API: %w", err)
			}
			return fmt.Errorf("telemt API did not become healthy within %s", timeout)
		case <-ticker.C:
		}
	}
}

// waitForReady polls /v1/health/ready for up to budget and returns the last
// reason telemt gave for not being ready.
func (m *MTProto) waitForReady(ctx context.Context, budget time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	ticker := time.NewTicker(readyPollInterval)
	defer ticker.Stop()

	var lastErr error
	for {
		err := m.apiClient.Ready(waitCtx)
		if err == nil {
			return nil
		}
		// Keep a real reason over the error of a request the deadline cut off.
		if lastErr == nil || waitCtx.Err() == nil {
			lastErr = err
		}

		select {
		case <-m.lifetime.Done():
			return errClosed
		case <-waitCtx.Done():
			return fmt.Errorf("not ready after %s: %w", budget, lastErr)
		case <-ticker.C:
		}
	}
}

// supervise restarts telemt whenever it is found not running, until
// Shutdown. The delay starts at supervisorInitialBackoff and doubles up to
// supervisorMaxBackoff; it resets once a telemt has stayed up that long.
func (m *MTProto) supervise() {
	backoff := supervisorInitialBackoff
	for {
		if exited := m.process.Exited(); exited != nil {
			watchedSince := time.Now()
			select {
			case <-exited:
			case <-m.lifetime.Done():
				return
			}
			if time.Since(watchedSince) >= supervisorMaxBackoff {
				backoff = supervisorInitialBackoff
			}
		}

		closed, running := m.supervisorState()
		if closed {
			return
		}
		if running {
			// A sync or Restart already started a new telemt.
			continue
		}

		if tail := m.process.StartupTail(telemtCrashTailSize); len(tail) > 0 {
			log.Printf("last %d telemt log lines:\n%s", len(tail), strings.Join(tail, "\n"))
		}
		log.Printf("telemt is not running, restarting it in %s", backoff)
		select {
		case <-time.After(backoff):
		case <-m.lifetime.Done():
			return
		}

		restarted, err := m.restartIfStopped()
		switch {
		case errors.Is(err, errClosed):
			return
		case err != nil:
			log.Printf("failed to restart telemt: %v", err)
		case !restarted:
			continue
		default:
			log.Println("telemt restarted")
		}
		backoff = min(backoff*2, supervisorMaxBackoff)
	}
}

func (m *MTProto) supervisorState() (closed, running bool) {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	return m.closed, m.process.Started()
}

// restartIfStopped starts telemt again unless it already runs, re-rendering
// the config from the current desired users.
func (m *MTProto) restartIfStopped() (bool, error) {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	if m.closed {
		return false, errClosed
	}
	if m.process.Started() {
		return false, nil
	}
	if err := m.writeRenderedConfigLocked(m.desired); err != nil {
		return false, err
	}
	if err := m.startLocked(m.lifetime); err != nil {
		return false, err
	}
	m.needsFullApply = false
	return true, nil
}
