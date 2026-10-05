package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	nodeLogger "github.com/pasarguard/node/logger"
	"github.com/pasarguard/node/pkg/netutil"
)

// ---------------------------------------------------------------------------
// A fake core, registered through the real seam.
//
// The fakes register on BackendType.HYSTERIA2 (the only enum value no shipped
// core claims) and dispatch on the config string, so three distinct cores can
// coexist without a second registration slot. Registering is exactly what a new
// core package does from its init(); if this test ever needs controller changes
// to add a core, the seam is broken.
// ---------------------------------------------------------------------------

var fakeType = common.BackendType_HYSTERIA2

type fakeCore struct {
	started   atomic.Bool
	shutdowns atomic.Int32
	starts    atomic.Int32
	logs      chan string

	ports     backend.Ports
	configDir string
	label     string
	listener  net.Listener
}

func (s *fakeCore) Started() bool   { return s.started.Load() }
func (s *fakeCore) Version() string { return "fake-" + s.label }
func (s *fakeCore) Logs() <-chan string {
	return s.logs
}
func (s *fakeCore) Restart() error { return nil }
func (s *fakeCore) Shutdown() {
	s.shutdowns.Add(1)
	s.started.Store(false)
	if s.listener != nil {
		_ = s.listener.Close()
	}
}
func (s *fakeCore) SyncUser(context.Context, *common.User) error                { return nil }
func (s *fakeCore) SyncUsers(context.Context, []*common.User) error             { return nil }
func (s *fakeCore) UpdateUsers(context.Context, []*common.User) error           { return nil }
func (s *fakeCore) UpdateUsersAndRestart(context.Context, []*common.User) error { return nil }
func (s *fakeCore) GetSysStats(context.Context) (*common.BackendStatsResponse, error) {
	return &common.BackendStatsResponse{}, nil
}
func (s *fakeCore) GetStats(context.Context, *common.StatRequest) (*common.StatResponse, error) {
	return &common.StatResponse{}, nil
}
func (s *fakeCore) GetOutboundsLatency(context.Context, *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{}, nil
}
func (s *fakeCore) GetUserOnlineStats(context.Context, string) (*common.OnlineStatResponse, error) {
	return &common.OnlineStatResponse{}, nil
}
func (s *fakeCore) GetUserOnlineIpListStats(context.Context, string) (*common.StatsOnlineIpListResponse, error) {
	return &common.StatsOnlineIpListResponse{}, nil
}

// statsCore returns fixed counters so the cross-core sum can be asserted.
// It also publishes a classified log channel, because a real xray/sing-box core
// does and the multiplexed GetLogs stream prefers that interface (CONTRACT §3.1).
type statsCore struct {
	*fakeCore
	rows     []*common.Stat
	logLines chan nodeLogger.LogLine
}

// LogLines is the classified channel the GetLogs handlers read when present.
func (s *statsCore) LogLines() <-chan nodeLogger.LogLine { return s.logLines }

// publish writes one classified line the way a real core does. It is a
// non-blocking send for the same reason a real core's is: a slow consumer must
// never wedge the core.
func (s *statsCore) publish(line nodeLogger.LogLine) {
	select {
	case s.logLines <- line:
	default:
	}
}

func (s *statsCore) GetStats(_ context.Context, req *common.StatRequest) (*common.StatResponse, error) {
	if req.GetReset_() {
		return &common.StatResponse{Stats: s.rows}, nil
	}
	return &common.StatResponse{Stats: s.rows}, nil
}

var (
	fakeMu      sync.Mutex
	fakeCores   = map[string]*statsCore{}   // config label -> latest instance
	fakeByDir   = map[string][]*statsCore{} // config dir -> every instance built there
	stealRecord atomic.Pointer[string]      // label whose factory must collide
)

// newFake records an instance and returns the stats view, which is what the
// Factory hands back: it embeds the core, so every Backend method is promoted.
func newFake(label, dir string, ports backend.Ports) *statsCore {
	fc := &fakeCore{logs: make(chan string, 4), label: label, configDir: dir, ports: ports}
	sc := &statsCore{fakeCore: fc, logLines: make(chan nodeLogger.LogLine, 64)}
	fakeMu.Lock()
	fakeCores[label] = sc
	fakeByDir[dir] = append(fakeByDir[dir], sc)
	fakeMu.Unlock()
	return sc
}

// fakeLookup returns the latest instance built for a config label.
func fakeLookup(t *testing.T, label string) *statsCore {
	t.Helper()
	fakeMu.Lock()
	defer fakeMu.Unlock()
	sc, ok := fakeCores[label]
	if !ok {
		t.Fatalf("fake core %q was never built", label)
	}
	return sc
}

func coreDir(base string, id uint64) string {
	return filepath.Join(base, fmt.Sprintf("core-%d", id))
}

// fakeGenerations counts how many process instances a core has been built with.
// Each instance starts exactly once, so this is the PID churn a restart causes.
func fakeGenerations(t *testing.T, base string, id uint64) int {
	t.Helper()
	fakeMu.Lock()
	n := len(fakeByDir[coreDir(base, id)])
	fakeMu.Unlock()
	if n == 0 {
		t.Fatalf("core %d has no recorded instance", id)
	}
	return n
}

// fakeShutdowns counts shutdowns across every instance of a core.
func fakeShutdowns(t *testing.T, base string, id uint64) int {
	t.Helper()
	fakeMu.Lock()
	hist := fakeByDir[coreDir(base, id)]
	fakeMu.Unlock()
	total := int32(0)
	for _, sc := range hist {
		total += sc.shutdowns.Load()
	}
	return int(total)
}

// bindFaker is a Factory whose only job is to bind the api port it is handed,
// so a port conflict is a real OS bind failure rather than a simulated one.
func bindFaker(ctx context.Context, in *common.Backend, ports backend.Ports, cfg *config.Config) (backend.Backend, error) {
	label := in.GetConfig()
	fc := newFake(label, cfg.GeneratedConfigPath, ports)

	if want := stealRecord.Load(); want != nil && *want == label {
		// Force the collision: ignore the port we were handed and take the one
		// another live core already owns. This is the only way to test the
		// conflict path — netutil.FindFreePort bind-tests, so it never returns a
		// port that is already in use.
		if other := livePeer(label); other != nil {
			fc.ports.ApiPort = other.ports.ApiPort
		}
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", fc.ports.ApiPort))
	if err != nil {
		return nil, err
	}
	fc.listener = ln
	// A real core's process dies on Shutdown; the listener must go with it, or
	// a re-enabled core finds its old port still held.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	fc.started.Store(true)
	fc.starts.Add(1)
	return fc, nil
}

// livePeer returns any started core other than the named one.
func livePeer(label string) *statsCore {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	for l, sc := range fakeCores {
		if l != label && sc.started.Load() {
			return sc
		}
	}
	return nil
}

func init() {
	backend.Register(fakeType, bindFaker)
}

func testController(t *testing.T) *Controller {
	t.Helper()
	cfg := config.NewTestConfig(t.TempDir(), uuid.New())
	c := New(cfg)
	t.Cleanup(c.Disconnect)
	return c
}

func startFake(t *testing.T, c *Controller, coreID uint64, label string, keepAlive uint64) error {
	t.Helper()
	c.LockControl(coreID)
	defer c.UnlockControl(coreID)
	return c.StartOrAttach(context.Background(), &common.Backend{
		Type:      fakeType,
		CoreId:    coreID,
		Config:    label,
		KeepAlive: keepAlive,
	})
}

func TestConnectCancelsPreviousStatsCollector(t *testing.T) {
	c := testController(t)

	ctx, cancel := context.WithCancel(context.Background())
	c.cancelFunc = cancel

	c.Connect(0)

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Connect did not cancel the previous stats collector")
	}
}

// TestThreeCoresOneNode: three cores live at once, each with its own ports and
// its own config directory, and killing one leaves the others up.
func TestThreeCoresOneNode(t *testing.T) {
	c := testController(t)

	for i, id := range []uint64{1, 2, 3} {
		if err := startFake(t, c, id, fmt.Sprintf("core%d", i), 0); err != nil {
			t.Fatalf("start core %d: %v", id, err)
		}
	}

	refs := c.StartedCores()
	if len(refs) != 3 {
		t.Fatalf("live cores = %d, want 3", len(refs))
	}

	seenPorts := map[int]uint64{}
	seenDirs := map[string]uint64{}
	for _, ref := range refs {
		fc := ref.Backend.(*statsCore)
		if !fc.Started() {
			t.Fatalf("core %d not started", ref.ID)
		}
		if fc.ports.ApiPort == 0 || fc.ports.MetricPort == 0 {
			t.Fatalf("core %d has no ports: %+v", ref.ID, fc.ports)
		}
		if prev, dup := seenPorts[fc.ports.ApiPort]; dup {
			t.Fatalf("cores %d and %d share apiPort %d", prev, ref.ID, fc.ports.ApiPort)
		}
		seenPorts[fc.ports.ApiPort] = ref.ID

		want := coreDir(c.cfg.GeneratedConfigPath, ref.ID)
		if fc.configDir != want {
			t.Fatalf("core %d config dir = %q, want %q", ref.ID, fc.configDir, want)
		}
		if prev, dup := seenDirs[fc.configDir]; dup {
			t.Fatalf("cores %d and %d share a config directory", prev, ref.ID)
		}
		seenDirs[fc.configDir] = ref.ID
	}

	c.DisconnectCore(1)

	if b, ok := c.BackendFor(1); ok && b.Started() {
		t.Fatal("core 1 still started after DisconnectCore(1)")
	}
	for _, id := range []uint64{2, 3} {
		b, ok := c.BackendFor(id)
		if !ok || !b.Started() {
			t.Fatalf("core %d stopped when core 1 was disconnected", id)
		}
	}
}

// TestIndependentLifecycle: stopping core A leaves B and C serving, and
// restarting B replaces only B's process.
func TestIndependentLifecycle(t *testing.T) {
	c := testController(t)

	for i, id := range []uint64{1, 2, 3} {
		if err := startFake(t, c, id, fmt.Sprintf("lc%d", i), 0); err != nil {
			t.Fatalf("start core %d: %v", id, err)
		}
	}

	// Core 1 is the legacy default core, so Backend() resolves to it; cores 2
	// and 3 must be untouched by its death.
	c.DisconnectCore(1)

	for _, id := range []uint64{2, 3} {
		b, ok := c.BackendFor(id)
		if !ok || !b.Started() {
			t.Fatalf("core %d stopped when core 1 was stopped", id)
		}
	}
	if b := c.Backend(); b != nil {
		t.Fatal("the legacy backend accessor still resolves to the stopped core 1")
	}

	c2Before, _ := c.BackendFor(2)
	first := fakeGenerations(t, c.cfg.GeneratedConfigPath, 2)
	if err := startFake(t, c, 2, "lc2", 0); err != nil {
		t.Fatalf("restart core 2: %v", err)
	}
	c2After, _ := c.BackendFor(2)
	if c2Before == c2After {
		t.Fatal("restarting core 2 reused its previous handle")
	}
	if c.Backend() != nil {
		t.Fatal("restarting core 2 resurrected the stopped core 1")
	}
	if second := fakeGenerations(t, c.cfg.GeneratedConfigPath, 2); second != first+1 {
		t.Fatalf("core 2 process generations = %d, want %d (only B restarted)", second, first+1)
	}
	if got := fakeShutdowns(t, c.cfg.GeneratedConfigPath, 2); got != 1 {
		t.Fatalf("core 2 shutdowns = %d, want 1 (only B was stopped)", got)
	}
	core3, _ := c.BackendFor(3)
	if core3 == nil || !core3.Started() {
		t.Fatal("core 3 stopped when core 2 was restarted")
	}
	if got := fakeShutdowns(t, c.cfg.GeneratedConfigPath, 3); got != 0 {
		t.Fatalf("core 3 shutdowns = %d, want 0 (only B was restarted)", got)
	}
}

// TestPortConflictNamesTheCore: a forced collision fails loudly, names the
// core, and leaves the core that owns the port untouched.
func TestPortConflictNamesTheCore(t *testing.T) {
	c := testController(t)

	if err := startFake(t, c, 1, "port-owner", 0); err != nil {
		t.Fatalf("start core 1: %v", err)
	}
	owner, _ := c.BackendFor(1)

	steal := "port-thief"
	stealRecord.Store(&steal)
	err := startFake(t, c, 2, "port-thief", 0)
	stealRecord.Store(nil)

	if err == nil {
		t.Fatal("two cores on one apiPort must not both start")
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("expected a bind error, got %T: %v", err, err)
	}
	if !contains(err.Error(), "core 2") {
		t.Fatalf("error does not name the failing core: %v", err)
	}

	if b, ok := c.BackendFor(1); !ok || b != owner || !owner.Started() {
		t.Fatal("the port owner was disturbed by the failed core")
	}
	if b, ok := c.BackendFor(2); ok && b.Started() {
		t.Fatal("the losing core is marked started")
	}

	var failed *common.CoreStatus
	for _, cs := range c.CoreStatuses() {
		if cs.GetCoreId() == 2 {
			failed = cs
		}
	}
	if failed == nil || failed.GetState() != coreStateFailed {
		t.Fatalf("core 2 status = %+v, want state failed", failed)
	}
	if failed.GetLastError() == "" {
		t.Fatal("failed core carries no last_error")
	}
}

// TestApiPortPlusOneReservation: no two cores are ever handed an apiPort whose
// successor another core already owns, because sing-box binds apiPort+1.
func TestApiPortPlusOneReservation(t *testing.T) {
	a := netutil.NewAllocator()

	apiPorts := map[int]bool{}
	metricPorts := map[int]bool{}
	for range 40 {
		api, metric := a.FindFreePorts()
		if api == 0 || metric == 0 {
			t.Fatalf("allocator ran out of ports: %d/%d", api, metric)
		}
		if apiPorts[api] {
			t.Fatalf("apiPort %d handed out twice", api)
		}
		for taken := range apiPorts {
			if taken == api+1 {
				t.Fatalf("core got apiPort %d whose successor %d belongs to another core", api, api+1)
			}
		}
		if metricPorts[metric] || metric == api || metric == api+1 {
			t.Fatalf("metricPort %d collides with the api pair %d/%d", metric, api, api+1)
		}
		apiPorts[api] = true
		metricPorts[metric] = true
		a.Reserve(api, metric)
	}
}

// TestReservedApiPortSuccessorIsNeverHandedOut pins the successor rule against a
// port that is known to be taken, rather than relying on a collision to appear.
func TestReservedApiPortSuccessorIsNeverHandedOut(t *testing.T) {
	a := netutil.NewAllocator()

	const victim = 45231
	a.Reserve(victim-1, 54321) // victim-1 owns victim as its quota port

	if !a.Taken(victim) {
		t.Fatal("Reserve must take apiPort+1 as well as apiPort")
	}
	for range 500 {
		api, _ := a.FindFreePorts()
		if api == victim-1 || api+1 == victim {
			t.Fatalf("allocator handed out %d whose successor %d is reserved", api, victim)
		}
	}
}

// TestHeartbeatIsPerCore: a changed config on core 1 restarts core 1 and leaves
// core 2's descriptor alone. This is the sameBackendConfig rule with two cores.
func TestHeartbeatIsPerCore(t *testing.T) {
	c := testController(t)

	if err := startFake(t, c, 1, "hb1a", 0); err != nil {
		t.Fatalf("start core 1: %v", err)
	}
	if err := startFake(t, c, 2, "hb2", 0); err != nil {
		t.Fatalf("start core 2: %v", err)
	}
	core2 := fakeLookup(t, "hb2")

	// Same config on core 1 is a heartbeat: nothing is rebuilt anywhere.
	c.LockControl(1)
	err := c.StartOrAttach(context.Background(), &common.Backend{
		Type: fakeType, CoreId: 1, Config: "hb1a", KeepAlive: 30,
	})
	c.UnlockControl(1)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if got := fakeLookup(t, "hb1a").shutdowns.Load(); got != 0 {
		t.Fatalf("heartbeat restarted core 1 (%d shutdowns)", got)
	}

	// A changed config on core 1 rebuilds core 1 only. The factory labels each
	// instance by its config string, so a rebuilt core 1 has a new handle.
	c.LockControl(1)
	restartErr := c.StartOrAttach(context.Background(), &common.Backend{
		Type: fakeType, CoreId: 1, Config: "hb1b", KeepAlive: 30,
	})
	c.UnlockControl(1)
	if restartErr != nil {
		t.Fatalf("restart core 1: %v", restartErr)
	}
	if got := fakeLookup(t, "hb1a").shutdowns.Load(); got != 1 {
		t.Fatalf("core 1 was not rebuilt: shutdowns = %d, want 1", got)
	}
	if got := core2.shutdowns.Load(); got != 0 {
		t.Fatalf("core 2 was restarted by core 1's config change (%d shutdowns)", got)
	}
	if b, _ := c.BackendFor(2); b != core2 {
		t.Fatal("core 2's descriptor changed when core 1 restarted")
	}
	if got := fakeGenerations(t, c.cfg.GeneratedConfigPath, 2); got != 1 {
		t.Fatalf("core 2 process generations = %d, want 1 (only core 1 rebuilt)", got)
	}
}

// TestKeepAliveIsPerCore: core 1 goes silent and is reaped; core 2 keeps
// serving because the panel keeps talking to it.
func TestKeepAliveIsPerCore(t *testing.T) {
	prevTick, prevGrace := keepAliveTick, keepAliveGrace
	keepAliveTick, keepAliveGrace = 20*time.Millisecond, 0
	t.Cleanup(func() { keepAliveTick, keepAliveGrace = prevTick, prevGrace })

	c := testController(t)

	if err := startFake(t, c, 1, "ka1", 1); err != nil {
		t.Fatalf("start core 1: %v", err)
	}
	if err := startFake(t, c, 2, "ka2", 1); err != nil {
		t.Fatalf("start core 2: %v", err)
	}
	silent := fakeLookup(t, "ka1")

	deadline := time.Now().Add(3 * time.Second)
	for {
		// The panel is still talking to core 2 and silent on core 1.
		c.NewCoreRequest(2)
		if silent.started.Load() == false {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("core 1 was never reaped after its keep-alive expired")
		}
		time.Sleep(20 * time.Millisecond)
	}

	b2, ok := c.BackendFor(2)
	if !ok || !b2.Started() {
		t.Fatal("core 2 was reaped alongside core 1")
	}
}

// TestEnableDisableReusesPorts: disabling a core stops only it; re-enabling
// starts it again with the same core_id and the same ports.
func TestEnableDisableReusesPorts(t *testing.T) {
	c := testController(t)

	if err := startFake(t, c, 1, "ed1", 0); err != nil {
		t.Fatalf("start core 1: %v", err)
	}
	if err := startFake(t, c, 2, "ed2", 0); err != nil {
		t.Fatalf("start core 2: %v", err)
	}
	before := fakeLookup(t, "ed2").ports

	c.DisconnectCore(2)

	if b, ok := c.BackendFor(2); ok && b.Started() {
		t.Fatal("core 2 still started after being disabled")
	}
	if b, ok := c.BackendFor(1); !ok || !b.Started() {
		t.Fatal("core 1 stopped when core 2 was disabled")
	}

	if err := startFake(t, c, 2, "ed2", 0); err != nil {
		t.Fatalf("re-enable core 2: %v", err)
	}
	after := fakeLookup(t, "ed2").ports
	if after.ApiPort != before.ApiPort || after.MetricPort != before.MetricPort {
		t.Fatalf("core 2 got new ports on re-enable: %+v -> %+v", before, after)
	}
	for _, cs := range c.CoreStatuses() {
		if cs.GetCoreId() == 2 && cs.GetType() != fakeType {
			t.Fatalf("core 2 type = %v, want the type it was started with", cs.GetType())
		}
	}
}

// TestBaseInfoListsEveryCore: BaseInfoResponse.cores carries every core's id,
// type, state and version, and started/core_version keep their legacy meaning.
func TestBaseInfoListsEveryCore(t *testing.T) {
	c := testController(t)

	if err := startFake(t, c, 1, "bi1", 0); err != nil {
		t.Fatalf("start core 1: %v", err)
	}
	if err := startFake(t, c, 2, "bi2", 0); err != nil {
		t.Fatalf("start core 2: %v", err)
	}

	info := c.BaseInfoResponse()
	if len(info.GetCores()) != 2 {
		t.Fatalf("cores = %d, want 2", len(info.GetCores()))
	}
	for i, want := range []struct {
		id    uint64
		label string
	}{{1, "bi1"}, {2, "bi2"}} {
		cs := info.GetCores()[i]
		if cs.GetCoreId() != want.id {
			t.Fatalf("cores[%d].core_id = %d, want %d", i, cs.GetCoreId(), want.id)
		}
		if cs.GetType() != fakeType {
			t.Fatalf("core %d type = %v, want %v", want.id, cs.GetType(), fakeType)
		}
		if cs.GetState() != coreStateHealthy {
			t.Fatalf("core %d state = %q, want healthy", want.id, cs.GetState())
		}
		if !cs.GetStarted() {
			t.Fatalf("core %d reports not started", want.id)
		}
		if cs.GetCoreVersion() != "fake-"+want.label {
			t.Fatalf("core %d version = %q", want.id, cs.GetCoreVersion())
		}
		if cs.GetUptimeSeconds() == 0 && time.Since(time.Now()) == 0 {
			continue // uptime is allowed to round to 0 for a sub-second core
		}
	}

	if !info.GetStarted() {
		t.Fatal("legacy started must stay true while the default core runs")
	}
	if info.GetCoreVersion() != "fake-bi1" {
		t.Fatalf("legacy core_version = %q, want the default core's", info.GetCoreVersion())
	}
	if info.GetNodeVersion() != NodeVersion {
		t.Fatalf("node_version = %q", info.GetNodeVersion())
	}
}

// TestCoreIDZeroIsTheDefaultCore: core_id 0 and core_id 1 are the same instance.
func TestCoreIDZeroIsTheDefaultCore(t *testing.T) {
	c := testController(t)

	c.LockControl(0)
	if err := c.StartOrAttach(context.Background(), &common.Backend{
		Type: fakeType, Config: "legacy", KeepAlive: 30,
	}); err != nil {
		c.UnlockControl(0)
		t.Fatalf("start via core_id 0: %v", err)
	}
	c.UnlockControl(0)

	byZero, ok := c.BackendFor(0)
	if !ok {
		t.Fatal("core_id 0 does not resolve")
	}
	byOne, ok := c.BackendFor(1)
	if !ok || byOne != byZero {
		t.Fatal("core_id 0 and core_id 1 resolve to different cores")
	}
	if c.Backend() != byZero {
		t.Fatal("the legacy Backend() accessor does not return core_id 0's core")
	}
	if got := fakeLookup(t, "legacy").configDir; got != filepath.Join(c.cfg.GeneratedConfigPath, "core-1") {
		t.Fatalf("core_id 0 landed in %q, want core-1", got)
	}
	if c.CoreIDOf(byZero) != 1 {
		t.Fatal("core_id 0's core is not reported as core 1")
	}

	// A heartbeat addressed to 0 must find the running core, not rebuild it.
	c.LockControl(0)
	err := c.StartOrAttach(context.Background(), &common.Backend{
		Type: fakeType, Config: "legacy", KeepAlive: 30,
	})
	c.UnlockControl(0)
	if err != nil {
		t.Fatalf("core_id 0 heartbeat: %v", err)
	}
	if got := fakeLookup(t, "legacy").shutdowns.Load(); got != 0 {
		t.Fatalf("core_id 0 heartbeat restarted the core (%d shutdowns)", got)
	}
}

// TestStatsSumAcrossCores: core_id 0 sums by name across every running core;
// core_id 3 addresses exactly one core.
func TestStatsSumAcrossCores(t *testing.T) {
	c := testController(t)

	if err := startFake(t, c, 1, "st1", 0); err != nil {
		t.Fatalf("start core 1: %v", err)
	}
	if err := startFake(t, c, 2, "st2", 0); err != nil {
		t.Fatalf("start core 2: %v", err)
	}

	st1, st2 := fakeLookup(t, "st1"), fakeLookup(t, "st2")
	st1.rows = []*common.Stat{{Name: "direct", Type: "uplink", Value: 100}}
	st2.rows = []*common.Stat{
		{Name: "direct", Type: "uplink", Value: 250},
		{Name: "block", Type: "uplink", Value: 7},
	}

	resp, err := c.Stats(context.Background(), &common.StatRequest{Reset_: true})
	if err != nil {
		t.Fatalf("aggregate stats: %v", err)
	}
	got := map[string]int64{}
	for _, stat := range resp.GetStats() {
		got[stat.GetName()] = stat.GetValue()
	}
	if got["direct"] != 350 {
		t.Fatalf("direct = %d, want the sum 350", got["direct"])
	}
	if got["block"] != 7 {
		t.Fatalf("block = %d, want 7", got["block"])
	}

	one, err := c.Stats(context.Background(), &common.StatRequest{CoreId: 2, Reset_: true})
	if err != nil {
		t.Fatalf("targeted stats: %v", err)
	}
	for _, stat := range one.GetStats() {
		if stat.GetName() == "direct" && stat.GetValue() != 250 {
			t.Fatalf("core 2 direct = %d, want 250 (core 2 only)", stat.GetValue())
		}
	}

	if _, err := c.Stats(context.Background(), &common.StatRequest{CoreId: 9}); err == nil {
		t.Fatal("a request for a core that is not running must fail")
	}
}

// TestUserSyncReachesEveryCore: a core_id-less sync fans out to all cores.
func TestUserSyncReachesEveryCore(t *testing.T) {
	c := testController(t)

	for i, id := range []uint64{1, 2} {
		if err := startFake(t, c, id, fmt.Sprintf("us%d", i), 0); err != nil {
			t.Fatalf("start core %d: %v", id, err)
		}
	}

	seen := map[uint64]int{}
	for _, ref := range c.StartedCores() {
		seen[ref.ID]++
	}
	if len(seen) != 2 {
		t.Fatalf("expected two reachable cores, got %v", seen)
	}

	if err := c.EachBackend(func(_ uint64, _ backend.Backend) error { return nil }); err != nil {
		t.Fatalf("EachBackend: %v", err)
	}
	if err := c.EachBackend(func(_ uint64, _ backend.Backend) error { return errors.New("boom") }); err == nil {
		t.Fatal("EachBackend must propagate a core's error")
	}
}

// TestDisconnectStopsEverything: Stop still means stop, and re-rolling the
// ports is the documented behaviour.
func TestDisconnectStopsEverything(t *testing.T) {
	c := testController(t)

	if err := startFake(t, c, 1, "disc1", 0); err != nil {
		t.Fatalf("start core 1: %v", err)
	}
	if err := startFake(t, c, 2, "disc2", 0); err != nil {
		t.Fatalf("start core 2: %v", err)
	}

	c.Disconnect()

	if len(c.StartedCores()) != 0 {
		t.Fatal("Disconnect left a core running")
	}
	if b := c.Backend(); b != nil {
		t.Fatal("Disconnect left the legacy backend accessor non-nil")
	}
	if got := fakeLookup(t, "disc1").shutdowns.Load(); got != 1 {
		t.Fatalf("core 1 shutdowns = %d, want 1", got)
	}
	if got := fakeLookup(t, "disc2").shutdowns.Load(); got != 1 {
		t.Fatalf("core 2 shutdowns = %d, want 1", got)
	}
}

func TestKeepAliveStaleIncludesGrace(t *testing.T) {
	now := time.Now()
	last := now.Add(-10 * time.Second)

	if keepAliveStale(last, 10*time.Second) {
		t.Fatal("keep-alive must not fire when silence equals keep_alive")
	}
	if !keepAliveStale(last.Add(-keepAliveGrace), 10*time.Second) {
		t.Fatal("keep-alive must fire after keep_alive plus grace")
	}
}

func TestUnknownBackendTypeNamesTheType(t *testing.T) {
	c := testController(t)

	c.LockControl(1)
	err := c.StartOrAttach(context.Background(), &common.Backend{Type: common.BackendType(99)})
	c.UnlockControl(1)

	if err == nil || !contains(err.Error(), "unknown backend type 99") {
		t.Fatalf("err = %v, want it to name the backend type", err)
	}
}

func TestEachBackendReportsNoCore(t *testing.T) {
	c := testController(t)

	err := c.EachBackend(func(_ uint64, _ backend.Backend) error { return nil })
	if err == nil || err.Error() != "backend not initialized" {
		t.Fatalf("err = %v, want backend not initialized", err)
	}
}

// contains is strings.Contains, kept local so this file needs no extra import
// for one call.
func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
