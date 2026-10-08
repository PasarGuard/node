package controller

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
	"github.com/pasarguard/node/pkg/sysstats"

	// Each core registers its Factory from an init(). The import is the wiring;
	// everything else a core needs arrives as a Factory parameter.
	_ "github.com/pasarguard/node/backend/hysteria"
	_ "github.com/pasarguard/node/backend/singbox"
	_ "github.com/pasarguard/node/backend/wireguard"
	_ "github.com/pasarguard/node/backend/xray"

	// The reference tunnel adapter registers itself the same way, so every
	// binary built on this controller can start a plain tunnel (CONTRACT §2).
	_ "github.com/pasarguard/node/backend/tunnel/plain"

	// The six pinned-binary tunnel adapters, same seam. Without these the
	// shipped node has only `plain` registered and every Start of a real tool
	// fails ErrUnknownTool — each tool's own test imports its package, so the
	// gap was invisible until the whole binary was asked for a gost tunnel.
	_ "github.com/pasarguard/node/backend/tunnel/amnezia"
	_ "github.com/pasarguard/node/backend/tunnel/backhaul"
	_ "github.com/pasarguard/node/backend/tunnel/chisel"
	_ "github.com/pasarguard/node/backend/tunnel/frp"
	_ "github.com/pasarguard/node/backend/tunnel/gost"
	_ "github.com/pasarguard/node/backend/tunnel/rathole"
	_ "github.com/pasarguard/node/backend/tunnel/wireguard"
	_ "github.com/pasarguard/node/backend/tunnel/wstunnel"
)

const NodeVersion = "0.5.4"

// keepAliveGrace is added to the configured keep-alive so a panel whose
// health interval equals keep_alive does not trip the watchdog on jitter. A var
// so a test can drive the watchdog fast.
var keepAliveGrace = 5 * time.Second

// keepAliveTick is the watchdog cadence. A test lowers it so a reaped core
// does not cost a five second sleep.
var keepAliveTick = 5 * time.Second

// Core states reported in BaseInfoResponse.cores (CONTRACT §3.4). A restart
// passes through "starting", so it needs no separate state.
const (
	coreStateStarting = "starting"
	coreStateHealthy  = "healthy"
	coreStateFailed   = "failed"
	coreStateStopped  = "stopped"
)

type Service interface {
	Disconnect()
}

// core is one running (or stopped) core instance: its own process, ports,
// config directory, keep-alive and state. Nothing here is shared with another
// core.
type core struct {
	id  uint64
	typ common.BackendType

	// ctl serialises start/stop of *this* core with its own keep-alive
	// watchdog. It is shared with Controller.controlMus so LockControl(id) and
	// the watchdog always contend on the same mutex — a watchdog tick for core B
	// must not block a start of core A.
	ctl *sync.Mutex

	backend    backend.Backend
	activeData *common.Backend
	cfg        *config.Config
	ports      backend.Ports
	hasPorts   bool

	state       string
	lastError   string
	startedAt   time.Time
	lastRequest time.Time
	keepAlive   time.Duration
	watchdog    context.CancelFunc
}

// CoreRef is a running core as seen by the RPC layer.
type CoreRef struct {
	ID      uint64
	Backend backend.Backend
}

type Controller struct {
	cfg   *config.Config
	mu    sync.RWMutex
	cores map[uint64]*core
	// controlMus is keyed by normalized core id and never shrinks: a lock must
	// outlive the instance that was created under it, so UnlockControl(id) can
	// never race a re-creation into a different mutex.
	controlMus map[uint64]*sync.Mutex
	ports      *netutil.Allocator

	stats           *common.SystemStatsResponse
	cancelFunc      context.CancelFunc
	nodeLastRequest time.Time
}

// normalizeCoreID maps the wire's 0 ("the node's default / only core") onto the
// instance it has always been: the first core, whose config directory is
// core-1 (CONTRACT §1.5).
func normalizeCoreID(id uint64) uint64 {
	if id == 0 {
		return 1
	}
	return id
}

func New(cfg *config.Config) *Controller {
	_, cancel := context.WithCancel(context.Background())
	return &Controller{
		cfg:        cfg,
		cores:      map[uint64]*core{},
		controlMus: map[uint64]*sync.Mutex{},
		ports:      netutil.NewAllocator(),
		cancelFunc: cancel,
	}
}

func (c *Controller) ApiKey() uuid.UUID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.ApiKey
}

// Role is the node's role (CONTRACT §1.7). The RPC middleware gates on it so
// a tunnel node answers with a reason instead of "backend not initialized".
func (c *Controller) Role() common.NodeRole {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.Role
}

// Config exposes the node config the controller was built with, so the RPC
// layer can point the tunnel manager at GeneratedConfigPath without a second
// copy of the config living in two places.
func (c *Controller) Config() *config.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg
}

// Connect starts the node-level stats collector and refreshes the node's own
// last-request stamp. Keep-alive is per core and armed by armKeepAlive; the
// argument is kept for the call signature StartOrAttach has always had.
func (c *Controller) Connect(keepAlive uint64) {
	c.mu.Lock()
	c.nodeLastRequest = time.Now()
	if c.cancelFunc != nil {
		c.cancelFunc()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancelFunc = cancel
	c.mu.Unlock()

	go c.recordSystemStats(ctx)
}

// Disconnect stops every core and releases every port. The next Start
// allocates fresh ones (CONTRACT §1.4).
func (c *Controller) Disconnect() {
	c.mu.Lock()
	if c.cancelFunc != nil {
		c.cancelFunc()
		c.cancelFunc = nil
	}
	backends := make([]backend.Backend, 0, len(c.cores))
	for id, co := range c.cores {
		if co.watchdog != nil {
			co.watchdog()
			co.watchdog = nil
		}
		if co.backend != nil {
			backends = append(backends, co.backend)
			co.backend = nil
		}
		co.activeData = nil
		co.state = coreStateStopped
		if co.hasPorts {
			c.ports.Release(co.ports.ApiPort, co.ports.MetricPort)
			co.hasPorts = false
		}
		delete(c.cores, id)
	}
	c.mu.Unlock()

	// Shutdown outside of the lock to avoid deadlock: Shutdown() waits for the
	// process to terminate.
	for _, b := range backends {
		b.Shutdown()
	}
}

// DisconnectCore stops one core and leaves every other core untouched. The
// stopped core keeps its instance and its ports, so a later Start with the same
// core_id reuses them (scope test 7).
func (c *Controller) DisconnectCore(coreID uint64) {
	id := normalizeCoreID(coreID)

	c.mu.Lock()
	co := c.cores[id]
	if co == nil {
		c.mu.Unlock()
		return
	}
	b := co.backend
	co.backend = nil
	co.activeData = nil
	co.state = coreStateStopped
	if co.watchdog != nil {
		co.watchdog()
		co.watchdog = nil
	}
	c.mu.Unlock()

	if b != nil {
		b.Shutdown()
	}
}

// LockControl takes the control mutex of one core. core_id 0 is the default
// core, which is core 1.
func (c *Controller) LockControl(coreID uint64) {
	c.controlMutex(coreID).Lock()
}

func (c *Controller) UnlockControl(coreID uint64) {
	c.controlMutex(coreID).Unlock()
}

func (c *Controller) controlMutex(coreID uint64) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.controlMutexLocked(normalizeCoreID(coreID))
}

func (c *Controller) controlMutexLocked(id uint64) *sync.Mutex {
	m, ok := c.controlMus[id]
	if !ok {
		m = &sync.Mutex{}
		c.controlMus[id] = m
	}
	return m
}

// NewRequest records one successful RPC that named no core. It refreshes the
// node's own stamp and the default core's keep-alive, which for a one-core node
// is every core — today's behaviour exactly. A second core's keep-alive is
// refreshed by the RPCs that address it (NewCoreRequest, Start, StopCore).
func (c *Controller) NewRequest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nodeLastRequest = time.Now()
	if def := c.defaultCoreLocked(1); def != nil {
		def.lastRequest = c.nodeLastRequest
	}
}

// NewCoreRequest records one successful RPC that named core coreID. coreID 0 is
// the default core, exactly as it is everywhere else.
func (c *Controller) NewCoreRequest(coreID uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if co, ok := c.cores[normalizeCoreID(coreID)]; ok {
		co.lastRequest = time.Now()
	}
}

// ensureCore returns the instance for a core id, creating it on first sight.
func (c *Controller) ensureCore(coreID uint64) *core {
	id := normalizeCoreID(coreID)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensureCoreLocked(id)
}

func (c *Controller) ensureCoreLocked(id uint64) *core {
	if co, ok := c.cores[id]; ok {
		return co
	}
	co := &core{
		id:    id,
		cfg:   c.cfg.ForCore(id),
		ctl:   c.controlMutexLocked(id),
		state: coreStateStopped,
	}
	c.cores[id] = co
	return co
}

// sameBackendConfig reports whether two Backend descriptors describe the same
// running configuration, users included.
//
// Users were excluded here on the assumption that they only change through their
// own sync RPCs. That is wrong: Start *replaces* the user set, so a Start whose
// list differs from the one the running core was built with has to be applied,
// not skipped as a heartbeat. The panel sends exactly such a Start whenever
// core_users filters a user out (User.status is limited/on_hold-gated), and
// treating it as a heartbeat left the core enforcing a budget the panel no
// longer agreed with.
func sameBackendConfig(active, incoming *common.Backend) bool {
	if active == nil || incoming == nil {
		return false
	}
	if active.GetType() != incoming.GetType() {
		return false
	}
	if active.GetConfig() != incoming.GetConfig() {
		return false
	}
	if !sameUserSet(active.GetUsers(), incoming.GetUsers()) {
		return false
	}
	// Compare exclude_inbounds as an ordered proto repeated field.
	tmp1 := &common.Backend{ExcludeInbounds: active.GetExcludeInbounds()}
	tmp2 := &common.Backend{ExcludeInbounds: incoming.GetExcludeInbounds()}
	return proto.Equal(tmp1, tmp2)
}

// sameUserSet reports whether two user lists describe the same set of users.
//
// Identity and credentials are compared, quota is not: the panel recomputes the
// remaining budget on every usage tick, so including it would make every
// heartbeat look like a change and restart the core once per tick. A moved
// budget is delivered by SyncUser/UpdateUsers, which is the path that exists to
// carry it without a restart.
func sameUserSet(active, incoming []*common.User) bool {
	if len(active) != len(incoming) {
		return false
	}
	for i, u := range incoming {
		a := active[i]
		if a.GetEmail() != u.GetEmail() {
			return false
		}
		if !proto.Equal(a.GetProxies(), u.GetProxies()) {
			return false
		}
		if !slices.Equal(a.GetInbounds(), u.GetInbounds()) {
			return false
		}
	}
	return true
}

// StartOrAttach starts the core named by data.core_id, or refreshes its
// keep-alive if that core is already running with the same config (heartbeat).
// It only restarts when:
//   - No backend is running for that core, or
//   - That core's backend has stopped, or
//   - The incoming config differs from what started it, including its user list
//     (see sameBackendConfig).
//
// core_id 0 addresses the default core and behaves exactly as the single-core
// node did.
//
// Caller must hold LockControl(data.core_id).
func (c *Controller) StartOrAttach(ctx context.Context, data *common.Backend) error {
	// Root-cause guard for the tunnel role (CONTRACT §1.7): a tunnel node
	// runs no proxy core and holds no users, so Start is refused here for
	// every transport — the gRPC middleware answers with the same error and a
	// FailedPrecondition code before it gets this far, and REST /start lands
	// here directly. One refusal, not one per caller.
	if c.cfg.IsTunnelRole() {
		return tunnel.ErrRoleRefused
	}
	id := normalizeCoreID(data.GetCoreId())
	co := c.ensureCore(id)

	c.mu.Lock()
	co.typ = data.GetType()
	running := co.backend
	active := co.activeData
	c.mu.Unlock()

	started := running != nil && running.Started()
	if started {
		if sameBackendConfig(active, data) {
			// Same config, backend healthy: this is a heartbeat. Just refresh.
			log.Println("StartOrAttach: backend already running with same config, refreshing keep-alive.")
			c.refreshKeepAlive(id, data.GetKeepAlive())
			c.Connect(data.GetKeepAlive())
			return nil
		}
		// Config changed while core is running: panel is sending a new config.
		log.Println("StartOrAttach: config changed, restarting backend.")
	} else if running != nil {
		// Backend object exists but has stopped.
		log.Println("StartOrAttach: replacing a backend that is no longer running.")
	}

	if running != nil {
		c.DisconnectCore(id)
	}
	if err := c.startCore(ctx, co, data); err != nil {
		return err
	}
	c.refreshKeepAlive(id, data.GetKeepAlive())
	c.Connect(data.GetKeepAlive())
	return nil
}

// refreshKeepAlive stamps this core's last request and (re)arms its watchdog.
func (c *Controller) refreshKeepAlive(coreID uint64, keepAlive uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	co := c.cores[normalizeCoreID(coreID)]
	if co == nil {
		return
	}
	co.lastRequest = time.Now()
	if co.watchdog != nil {
		co.watchdog()
		co.watchdog = nil
	}
	if keepAlive == 0 {
		return
	}
	co.keepAlive = time.Duration(keepAlive) * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	co.watchdog = cancel
	go c.keepAliveTracker(ctx, co)
}

// startCore builds one core instance through the registered Factory. Ports are
// allocated once per core instance and kept; the config path is already scoped
// to core-<id> by ensureCore.
func (c *Controller) startCore(ctx context.Context, co *core, data *common.Backend) error {
	factory, ok := backend.For(data.GetType())
	if !ok {
		return fmt.Errorf("unknown backend type %v", data.GetType())
	}

	c.mu.Lock()
	if !co.hasPorts {
		apiPort, metricPort := c.ports.FindFreePorts()
		c.ports.Reserve(apiPort, metricPort)
		co.ports = backend.Ports{ApiPort: apiPort, MetricPort: metricPort}
		co.hasPorts = true
	}
	ports := co.ports
	coreCfg := co.cfg
	co.state = coreStateStarting
	c.mu.Unlock()

	b, err := factory(ctx, data, ports, coreCfg)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		co.backend = nil
		co.activeData = nil
		co.state = coreStateFailed
		// Name the core: a failed core on a node running several must be
		// identifiable from the panel's log line alone.
		co.lastError = fmt.Sprintf("core %d: %v", co.id, err)
		return fmt.Errorf("core %d: %w", co.id, err)
	}
	co.backend = b
	co.activeData = data
	co.state = coreStateHealthy
	co.lastError = ""
	co.startedAt = time.Now()
	return nil
}

// Backend returns the default core's backend (core_id 0 / core 1), which is
// what every pre-existing single-core caller means.
func (c *Controller) Backend() backend.Backend {
	c.mu.RLock()
	defer c.mu.RUnlock()
	co := c.defaultCoreLocked(1)
	if co == nil {
		return nil
	}
	return co.backend
}

// BackendFor returns one core's backend. coreID 0 resolves to the default core.
//
// A NAMED core resolves to itself or to nothing. Falling back to the default
// core for a core id that does not exist would be wrong for every caller that
// named one deliberately — the RPC gate would admit a request for core 99 into
// core 1's stats, and the panel would bill one core's traffic under another's
// answer. Only core_id 0 (the node's default / only core, CONTRACT §1.2) gets the
// default-core fallback.
func (c *Controller) BackendFor(coreID uint64) (backend.Backend, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if coreID == 0 {
		co := c.defaultCoreLocked(1)
		if co == nil || co.backend == nil {
			return nil, false
		}
		return co.backend, true
	}

	co, ok := c.cores[coreID]
	if !ok || co.backend == nil {
		return nil, false
	}
	return co.backend, true
}

// CoreIDOf reports which core owns a backend, so a record can be attributed to
// the core that produced it.
func (c *Controller) CoreIDOf(b backend.Backend) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, id := range sortedCoreIDs(c.cores) {
		if c.cores[id].backend == b {
			return id
		}
	}
	return 0
}

// EachBackend calls fn on every running core. A user sync with no core_id
// broadcasts: every core keeps the subset whose inbounds match.
func (c *Controller) EachBackend(fn func(id uint64, b backend.Backend) error) error {
	// Backstop for the tunnel role: a user sync on a tunnel node is refused
	// with the reason, not with "backend not initialized" — no core will ever
	// exist there to make that message true.
	if c.cfg.IsTunnelRole() {
		return tunnel.ErrRoleRefused
	}
	refs := c.StartedCores()
	if len(refs) == 0 {
		return errNoCoreRunning
	}
	for _, ref := range refs {
		if err := fn(ref.ID, ref.Backend); err != nil {
			return err
		}
	}
	return nil
}

// StartedCores returns every running core in id order. An empty result is the
// "backend not initialized" case every caller already handles.
func (c *Controller) StartedCores() []CoreRef {
	c.mu.RLock()
	defer c.mu.RUnlock()
	refs := make([]CoreRef, 0, len(c.cores))
	for _, id := range sortedCoreIDs(c.cores) {
		co := c.cores[id]
		if co.backend == nil || !co.backend.Started() {
			continue
		}
		refs = append(refs, CoreRef{ID: id, Backend: co.backend})
	}
	return refs
}

// LogSources returns every running core with its id, in id order, for the
// multiplexed GetLogs stream (CONTRACT §3.1).
func (c *Controller) LogSources() []CoreRef {
	return c.StartedCores()
}

// defaultCoreLocked is the core a legacy caller means: core 1 when it exists,
// otherwise the lowest id (a panel that only ever used core_id 0 always has a 1).
func (c *Controller) defaultCoreLocked(prefer uint64) *core {
	if co, ok := c.cores[prefer]; ok {
		return co
	}
	ids := sortedCoreIDs(c.cores)
	if len(ids) == 0 {
		return nil
	}
	return c.cores[ids[0]]
}

// errNoCoreRunning is what every handler already turns into
// codes.Unavailable / HTTP 503.
var errNoCoreRunning = errors.New("backend not initialized")

// Stats answers a StatRequest for one core, or — when core_id is 0 — the sum
// across every running core.
//
// The aggregate is what keeps the panel's usage jobs working unchanged: they ask
// for one number per name and now get the node's total (CONTRACT §3.2). A
// targeted request never mixes cores.
func (c *Controller) Stats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	refs := c.StartedCores()
	if len(refs) == 0 {
		return nil, errNoCoreRunning
	}

	if id := request.GetCoreId(); id != 0 {
		want := normalizeCoreID(id)
		for _, ref := range refs {
			if ref.ID == want {
				return ref.Backend.GetStats(ctx, request)
			}
		}
		return nil, fmt.Errorf("core %d is not running", id)
	}

	// ponytail: one request per core; add a batched form if a node's core count
	// ever makes this latency visible.
	sums := map[string]*common.Stat{}
	order := make([]string, 0, len(refs))
	for _, ref := range refs {
		resp, err := ref.Backend.GetStats(ctx, request)
		if err != nil {
			return nil, err
		}
		for _, stat := range resp.GetStats() {
			// Type and link are part of a row's identity: two cores reporting the
			// same name under different links stay separate rows.
			key := stat.GetName() + "\x00" + stat.GetType() + "\x00" + stat.GetLink()
			acc, ok := sums[key]
			if !ok {
				acc = &common.Stat{Name: stat.GetName(), Type: stat.GetType(), Link: stat.GetLink()}
				sums[key] = acc
				order = append(order, key)
			}
			acc.Value += stat.GetValue()
		}
	}

	out := &common.StatResponse{Stats: make([]*common.Stat, 0, len(order))}
	for _, key := range order {
		out.Stats = append(out.Stats, sums[key])
	}
	return out, nil
}

func sortedCoreIDs(cores map[uint64]*core) []uint64 {
	ids := make([]uint64, 0, len(cores))
	for id := range cores {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func keepAliveStale(lastRequest time.Time, keepAlive time.Duration) bool {
	now := time.Now()
	return now.Sub(lastRequest) >= keepAlive+keepAliveGrace
}

// keepAliveTracker reaps one core whose panel stopped talking to it. It takes
// that core's control mutex, so a reap of core B never blocks a start of core A.
func (c *Controller) keepAliveTracker(ctx context.Context, co *core) {
	ticker := time.NewTicker(keepAliveTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			stale := keepAliveStale(co.lastRequest, co.keepAlive)
			c.mu.RUnlock()
			if !stale {
				continue
			}

			// Serialize with Start/Stop of this core so a late watchdog cannot
			// kill a core that startCore just created.
			co.ctl.Lock()
			c.mu.RLock()
			stale = keepAliveStale(co.lastRequest, co.keepAlive)
			c.mu.RUnlock()
			// A rearm for a fresh Start cancels this watchdog's context; the
			// new watchdog owns the reap, this one must stand down.
			if stale && ctx.Err() == nil {
				log.Printf("disconnect core %d automatically due to keep alive timeout", co.id)
				c.DisconnectCore(co.id)
			}
			co.ctl.Unlock()
			return
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
	backendSnapshot := c.defaultCoreLocked(1)
	var back backend.Backend
	if backendSnapshot != nil {
		back = backendSnapshot.backend
	}
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

	if back == nil {
		return response
	}

	// Backend uptime is owned by each backend implementation; controller only forwards it here.
	// ponytail: the default core's uptime stands for the node — per-core uptime is in BaseInfoResponse.cores
	backendStats, err := back.GetSysStats(ctx)
	if err != nil {
		log.Printf("Failed to get backend uptime for system stats: %v", err)
		return response
	}

	response.Uptime = uint64(backendStats.GetUptime())
	return response
}

// CoreStatuses reports every known core (running or stopped) for
// BaseInfoResponse.cores (CONTRACT §3.4).
func (c *Controller) CoreStatuses() []*common.CoreStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()

	statuses := make([]*common.CoreStatus, 0, len(c.cores))
	for _, id := range sortedCoreIDs(c.cores) {
		co := c.cores[id]
		cs := &common.CoreStatus{
			CoreId:    id,
			Type:      co.typ,
			State:     co.state,
			LastError: co.lastError,
		}
		if co.backend != nil {
			cs.Started = co.backend.Started()
			cs.CoreVersion = co.backend.Version()
			if cs.Started && !co.startedAt.IsZero() {
				cs.UptimeSeconds = uint64(time.Since(co.startedAt).Seconds())
			}
			if cs.Started && cs.State == "" {
				cs.State = coreStateHealthy
			}
		}
		statuses = append(statuses, cs)
	}
	return statuses
}

func (c *Controller) BaseInfoResponse() *common.BaseInfoResponse {
	response := &common.BaseInfoResponse{
		Started:     false,
		CoreVersion: "",
		NodeVersion: NodeVersion,
		Cores:       c.CoreStatuses(),
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if def := c.defaultCoreLocked(1); def != nil && def.backend != nil {
		// started/core_version keep their single-core meaning (the default
		// core's reading), so an unmodified panel still reads sensibly
		// (CONTRACT §3.4).
		response.Started = def.backend.Started()
		response.CoreVersion = def.backend.Version()
	}

	return response
}

func (c *Controller) OutboundsLatency(ctx context.Context, request *common.LatencyRequest) (*common.LatencyResponse, error) {
	// ponytail: latency of the default core; per-core latency is not a contract shape
	backendSnapshot := c.Backend()

	if backendSnapshot == nil {
		return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
	}

	return backendSnapshot.GetOutboundsLatency(ctx, request)
}
