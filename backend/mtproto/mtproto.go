package mtproto

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pasarguard/node/config"
)

type MTProto struct {
	cfg            *config.Config
	config         *Config
	process        *processManager
	configPath     string
	apiClient      *apiClient
	metricsScraper *metricsScraper
	tracker        *trafficTracker

	apiPort       int
	metricsPort   int
	apiAuthHeader string

	// syncMu serializes every operation that changes users or the telemt
	// process: syncs, restarts, the supervisor and Shutdown. A full apply
	// holds it until telemt's verdict, even after its caller gave up.
	syncMu syncLock
	closed bool // guarded by syncMu
	// needsFullApply is set when telemt may run users other than desired: a
	// reload whose outcome is unknown, or user API calls that failed midway.
	// The next sync then renders and reloads every user. Guarded by syncMu.
	needsFullApply bool
	// apiSent holds the users written through telemt's user API since the
	// last confirmed render or telemt start. Guarded by syncMu.
	apiSent map[string]apiWrite

	// stateMu guards desired and marker for readers; writers also hold
	// syncMu. desired holds only users telemt confirmed it runs. marker is
	// the disabled user of the latest render, never a real user.
	stateMu sync.RWMutex
	desired map[string]*runtimeUser
	marker  *runtimeUser

	// refreshMu serializes stats refreshes, so snapshots reach tracker in
	// the order telemt produced them; it guards refresh. Stats readers never
	// take syncMu.
	refreshMu sync.Mutex
	refresh   refreshState
	// statsClock is the time source of refreshes; nil means time.Now.
	statsClock func() time.Time

	// lifetime is cancelled by Shutdown so waits for telemt stop early.
	lifetime context.Context
	cancel   context.CancelFunc
	// background tracks the supervisor and readiness watchers.
	background sync.WaitGroup
}

func (m *MTProto) Started() bool {
	return m.process.Started()
}

func (m *MTProto) Version() string {
	return m.process.Version()
}

func (m *MTProto) SubscribeLogs(ctx context.Context) <-chan string {
	return m.process.SubscribeLogs(ctx)
}

func (m *MTProto) Restart() error {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	if m.closed {
		return errClosed
	}
	if err := m.writeRenderedConfigLocked(m.desired); err != nil {
		return err
	}
	m.process.Stop()
	if err := m.startLocked(m.lifetime); err != nil {
		return err
	}
	m.needsFullApply = false
	return nil
}

// markerUsernamePrefix starts every marker username. Panel usernames are
// numeric user ids, so no real user has it.
const markerUsernamePrefix = "pgm_"

// markerUsername returns the marker user of the latest render. Stats must
// never report it; older markers share markerUsernamePrefix.
func (m *MTProto) markerUsername() string {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	if m.marker == nil {
		return ""
	}
	return m.marker.Username
}

// newMarkerUser returns a marker user with a fresh random name and secret.
// Every render carries one, disabled: once telemt's running config has it,
// telemt has published that render (its user admission follows from the
// published config shortly after). It also keeps telemt's user list
// non-empty.
func newMarkerUser() (*runtimeUser, error) {
	secret := make([]byte, 16)
	usernameSuffix := make([]byte, 8)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate the mtproto marker secret: %w", err)
	}
	if _, err := rand.Read(usernameSuffix); err != nil {
		return nil, fmt.Errorf("failed to generate the mtproto marker username: %w", err)
	}

	return &runtimeUser{
		Username: markerUsernamePrefix + hex.EncodeToString(usernameSuffix),
		Secret:   hex.EncodeToString(secret),
	}, nil
}

func generateBearerToken() (string, error) {
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return "Bearer " + hex.EncodeToString(token), nil
}

func cloneRuntimeUserMap(input map[string]*runtimeUser) map[string]*runtimeUser {
	cloned := make(map[string]*runtimeUser, len(input))
	for username, user := range input {
		if user == nil {
			continue
		}
		copyUser := *user
		cloned[username] = &copyUser
	}
	return cloned
}

// writeFileAtomic writes payload to path via a temp file and rename. The
// rendered config holds the API bearer token and per-user secrets, so the
// directory and file are created with owner-only permissions.
func writeFileAtomic(path string, payload []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tempFile, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	defer func() { _ = os.Remove(tempPath) }()

	if _, err := tempFile.Write(payload); err != nil {
		_ = tempFile.Close()
		return err
	}
	if err := tempFile.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
