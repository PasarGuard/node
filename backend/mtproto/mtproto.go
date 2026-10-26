package mtproto

import (
	"context"
	"sync"
	"time"
)

// MTProto runs telemt as the node's MTProto proxy backend: it renders the
// panel config plus the users into telemt's config file, supervises the
// telemt process (lifecycle.go), applies user changes through telemt's user
// API or a hot reload (sync.go, reload.go) and reads traffic from telemt's
// metrics (stats.go).
type MTProto struct {
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
	// healthyAt is when the running telemt's API first answered. Guarded by
	// syncMu.
	healthyAt time.Time

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
