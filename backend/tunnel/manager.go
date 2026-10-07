package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	nodeLogger "github.com/pasarguard/node/logger"
)

// DefaultRing is how many log records one running side keeps in memory. The
// node's own LOG_BUFFER_SIZE default is much larger; a tunnel's line rate is
// low and the ring is a status view, not an audit trail (the panel keeps the
// history it persists).
const DefaultRing = 500

// ManagerOptions configures a Manager. Dir is the persistence directory: set
// on a node (one JSON file per running side, so a tunnel comes back from
// config alone after a process restart), and a t.TempDir() in tests.
type ManagerOptions struct {
	Dir       string
	BundleDir string // "" reads TUNNEL_BUNDLE_DIR at resolve time
	Ring      int    // 0 → DefaultRing
	Allocator *Allocator
}

// Status is one running side, as reported over TunnelStatus (CONTRACT §4.3).
// State uses the core vocabulary of §3.4 — starting|healthy|failed|stopped —
// so a panel that already maps core states maps tunnel states the same way.
type Status struct {
	TunnelID      string
	Side          string
	Tool          string
	Mode          string
	State         string
	LastError     string
	Version       string
	UptimeSeconds uint64
	BytesUp       uint64
	BytesDown     uint64
}

// Record is one log record, tagged with tunnel_id (CONTRACT §3.1 vocabulary).
type Record struct {
	TunnelID string
	Level    string
	TsUnixMs int64
	Detail   string
}

type instance struct {
	spec    Spec
	ports   Ports
	handle  Handle
	started time.Time

	mu    sync.Mutex
	lines []Record
}

// Manager runs the tunnels this node hosts: one instance per (tunnel_id,
// side). It owns the port allocator, the per-tunnel log rings, and the
// persistence that makes a tunnel come back after a process restart.
//
// A tunnel is not keep-alive governed (unlike a core): nothing here reaps on a
// panel heartbeat. The panel reads List on its own schedule; StopTunnel is the
// only thing that takes a tunnel down.
type Manager struct {
	opts  ManagerOptions
	alloc *Allocator
	// startMu serialises Start with itself: two concurrent Starts for the same
	// (tunnel_id, side) would otherwise both detach-and-bind the same ports.
	startMu sync.Mutex

	mu      sync.Mutex
	running map[string]*instance
	subs    map[chan Record]struct{}
}

// NewManager returns a Manager. An empty Dir disables persistence (tests that
// must not write anywhere get that for free).
func NewManager(opts ManagerOptions) *Manager {
	if opts.Ring <= 0 {
		opts.Ring = DefaultRing
	}
	if opts.Allocator == nil {
		opts.Allocator = NewAllocator()
	}
	return &Manager{
		opts:    opts,
		alloc:   opts.Allocator,
		running: map[string]*instance{},
		subs:    map[chan Record]struct{}{},
	}
}

// Alloc exposes the manager's allocator so a caller (the RPC layer) can hand
// ports to Start that the manager is able to release again on Stop.
func (m *Manager) Alloc() *Allocator { return m.alloc }

// Dir is where persisted tunnel configs live ("" when persistence is off).
func (m *Manager) Dir() string { return m.opts.Dir }

func instanceKey(id string, side Side) string { return id + "\x00" + side.String() }

// ResolveFromEnv fills every Secrets entry whose value is still empty from the
// environment variable of the same name. Entries already carrying a value are
// left alone — that is what lets a caller plant a deliberate wrong value (the
// testkit's negative control) without it being overwritten.
//
// An empty entry with no matching, non-empty environment variable is an error:
// Start refuses rather than running unauthenticated.
func (s *Spec) ResolveFromEnv() error {
	if len(s.Secrets) == 0 {
		return nil
	}
	for name, v := range s.Secrets {
		if v != "" {
			continue
		}
		ev, ok := os.LookupEnv(name)
		if !ok || ev == "" {
			return fmt.Errorf("%w: environment variable %q is not set", ErrSecretUnresolved, name)
		}
		s.Secrets[name] = ev
	}
	return nil
}

// Start brings one side up: resolve secrets, check the pin, hand the spec to
// the adapter, tag its log line channel with this tunnel_id, persist.
//
// An instance already running under the same (tunnel_id, side) is stopped
// first — a Start that changes the config restarts the side, exactly like a
// core's StartOrAttach.
func (m *Manager) Start(ctx context.Context, spec Spec, ports Ports) error {
	m.startMu.Lock()
	defer m.startMu.Unlock()

	if err := spec.Validate(); err != nil {
		return err
	}
	adapter, err := Require(spec.Tool)
	if err != nil {
		return err
	}

	pspec := spec.Clone()
	if err := pspec.ResolveFromEnv(); err != nil {
		return err
	}

	// Install rule (CONTRACT §2.1): a tool with a pin runs only the binary
	// whose sha256 matches it. The path is handed to the tool so it does not
	// resolve a second, different candidate.
	if _, ok := PinFor(spec.Tool); ok {
		bin, err := ResolveBinary(spec.Tool, m.opts.BundleDir)
		if err != nil {
			return err
		}
		if pspec.Params == nil {
			pspec.Params = map[string]string{}
		}
		pspec.Params[ParamBinaryPath] = bin
	}
	if m.opts.Dir != "" {
		dir := filepath.Join(m.opts.Dir, safeDirName(spec.TunnelID), spec.Side.String())
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("tunnel: config dir: %w", err)
		}
		if pspec.Params == nil {
			pspec.Params = map[string]string{}
		}
		pspec.Params[ParamConfigDir] = dir
	}

	// A Start that changes the config restarts the side; the previous
	// instance must be fully down (ports released, process gone) before the
	// adapter binds them again, so Shutdown runs synchronously here.
	if prev := m.detach(spec.TunnelID, spec.Side, false); prev != nil {
		prev.handle.Shutdown()
	}

	handle, err := adapter.Start(ctx, pspec, ports)
	if err != nil {
		return fmt.Errorf("tunnel %s/%s (%s): %w", spec.TunnelID, spec.Side, spec.Tool, err)
	}

	inst := &instance{spec: pspec, ports: ports, handle: handle, started: time.Now()}
	key := instanceKey(spec.TunnelID, spec.Side)
	m.mu.Lock()
	m.running[key] = inst
	m.mu.Unlock()

	go m.pump(inst)

	if err := m.persist(pspec, ports); err != nil {
		// The tunnel is up; failing the start over a bookkeeping write would
		// take down live traffic. Say it and continue.
		log.Printf("[Warning] tunnel %s: could not persist config: %v", pspec.TunnelID, err)
	}
	return nil
}

// Stop takes down every side of a tunnel this node runs and removes its
// persisted config, so a process restart does not bring it back. That is the
// difference from Shutdown: Stop is the panel saying "no longer", Shutdown is
// the process going away.
func (m *Manager) Stop(tunnelID string) error {
	if !validTunnelID(tunnelID) {
		return fmt.Errorf("%w: tunnel_id %q", ErrInvalidSpec, tunnelID)
	}
	stopped := 0
	for _, side := range []Side{SideA, SideB} {
		if inst := m.detach(tunnelID, side, true); inst != nil {
			inst.handle.Shutdown()
			stopped++
		}
	}
	if stopped == 0 {
		return fmt.Errorf("%w: tunnel %s", ErrNotRunning, tunnelID)
	}
	return nil
}

// detach removes one instance from the running set, releases its ports and
// (when removeFile) its persisted config. It returns the instance so the
// caller can run the blocking Shutdown outside the lock; nil when that
// (tunnel_id, side) is not running. A config-changing Start calls it with
// removeFile=false and persists again straight after.
func (m *Manager) detach(tunnelID string, side Side, removeFile bool) *instance {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := instanceKey(tunnelID, side)
	inst, ok := m.running[key]
	if !ok {
		return nil
	}
	delete(m.running, key)
	m.alloc.Release(inst.ports)
	if removeFile {
		m.removePersist(tunnelID, side)
	}
	return inst
}

// List reports every running side, in (tunnel_id, side) order.
func (m *Manager) List() []Status {
	m.mu.Lock()
	insts := make([]*instance, 0, len(m.running))
	for _, inst := range m.running {
		insts = append(insts, inst)
	}
	m.mu.Unlock()

	sort.Slice(insts, func(i, j int) bool {
		if insts[i].spec.TunnelID != insts[j].spec.TunnelID {
			return insts[i].spec.TunnelID < insts[j].spec.TunnelID
		}
		return insts[i].spec.Side < insts[j].spec.Side
	})

	out := make([]Status, 0, len(insts))
	for _, inst := range insts {
		out = append(out, m.statusOf(inst))
	}
	return out
}

// Status reports the first matching side of a tunnel (a node normally runs
// exactly one side per tunnel_id).
func (m *Manager) Status(tunnelID string) (Status, bool) {
	for _, st := range m.List() {
		if st.TunnelID == tunnelID {
			return st, true
		}
	}
	return Status{}, false
}

func (m *Manager) statusOf(inst *instance) Status {
	st := Status{
		TunnelID: inst.spec.TunnelID,
		Side:     inst.spec.Side.String(),
		Tool:     inst.spec.Tool,
		Mode:     inst.spec.Mode,
		State:    "stopped",
	}
	if inst.handle.Started() {
		st.State = "healthy"
		st.UptimeSeconds = uint64(time.Since(inst.started).Seconds())
		if v := inst.handle.Version(); v != "" {
			st.Version = v
		}
		if b, err := inst.handle.Stats(context.Background()); err == nil {
			st.BytesUp, st.BytesDown = b.Up, b.Down
		}
	}
	return st
}

// Logs returns the retained records of every side of tunnelID, oldest first.
func (m *Manager) Logs(tunnelID string) []Record {
	m.mu.Lock()
	var insts []*instance
	for _, inst := range m.running {
		if inst.spec.TunnelID == tunnelID {
			insts = append(insts, inst)
		}
	}
	m.mu.Unlock()

	var out []Record
	for _, inst := range insts {
		inst.mu.Lock()
		out = append(out, inst.lines...)
		inst.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TsUnixMs < out[j].TsUnixMs })
	return out
}

// Subscribe returns a live stream of records from every tunnel on this node,
// plus a cancel func. The RPC layer stamps tunnel_id per record; the panel
// filters client-side, same as GetLogs does with core_id (CONTRACT §3.1).
//
// A subscriber that stops reading loses records rather than blocking a tunnel:
// the channel is buffered and the send is best-effort. Log volume on a node is
// small; a slow consumer must never stall a data path.
func (m *Manager) Subscribe(buffer int) (<-chan Record, func()) {
	if buffer <= 0 {
		buffer = 256
	}
	ch := make(chan Record, buffer)
	m.mu.Lock()
	m.subs[ch] = struct{}{}
	m.mu.Unlock()
	return ch, func() {
		m.mu.Lock()
		if _, ok := m.subs[ch]; ok {
			delete(m.subs, ch)
			close(ch)
		}
		m.mu.Unlock()
	}
}

// Shutdown stops every side but leaves the persisted config alone, so the next
// process start restores the same tunnels.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	ids := map[string]bool{}
	for key := range m.running {
		if i := strings.IndexByte(key, 0); i >= 0 {
			ids[key[:i]] = true
		}
	}
	m.mu.Unlock()

	for id := range ids {
		for _, side := range []Side{SideA, SideB} {
			if inst := m.detach(id, side, false); inst != nil {
				inst.handle.Shutdown()
			}
		}
	}

	// Drain subscribers so a streaming RPC ends instead of hanging.
	m.mu.Lock()
	for ch := range m.subs {
		delete(m.subs, ch)
		close(ch)
	}
	m.mu.Unlock()
}

// Restore loads every persisted tunnel and starts it: config alone, no RPC
// (scope test 4 — a tunnel comes back after the node process restarts).
// A tunnel whose secrets are missing from the environment is skipped with a
// log line rather than taking the node down.
func (m *Manager) Restore(ctx context.Context) (started int, err error) {
	if m.opts.Dir == "" {
		return 0, nil
	}
	files, err := filepath.Glob(filepath.Join(m.opts.Dir, "*.tunnel.json"))
	if err != nil {
		return 0, err
	}
	sort.Strings(files)
	for _, file := range files {
		rec, err := readPersisted(file)
		if err != nil {
			log.Printf("[Warning] tunnel restore %s: %v", file, err)
			continue
		}
		if err := m.Start(ctx, rec.Spec, rec.Ports); err != nil {
			log.Printf("[Warning] tunnel restore %s (%s): %v", rec.Spec.TunnelID, rec.Spec.Tool, err)
			continue
		}
		started++
	}
	return started, nil
}

// pump tags every line from one handle with this tunnel's id, keeps the ring,
// and fans the record out to subscribers.
func (m *Manager) pump(inst *instance) {
	if liner, ok := inst.handle.(nodeLogger.LogLiner); ok {
		// Call LogLines once: a tool that builds a fresh channel per call
		// would otherwise lose every line published before the second call.
		if ch := liner.LogLines(); ch != nil {
			for line := range ch {
				m.record(inst, Record{
					TunnelID: inst.spec.TunnelID,
					Level:    string(line.Level),
					TsUnixMs: line.TsUnixMs,
					Detail:   line.Detail,
				})
			}
			return
		}
	}
	for line := range inst.handle.Logs() {
		m.record(inst, Record{
			TunnelID: inst.spec.TunnelID,
			Level:    classifyLevel(line),
			TsUnixMs: time.Now().UnixMilli(),
			Detail:   line,
		})
	}
}

func (m *Manager) record(inst *instance, rec Record) {
	if rec.TsUnixMs == 0 {
		rec.TsUnixMs = time.Now().UnixMilli()
	}
	if rec.Level == "" {
		rec.Level = classifyLevel(rec.Detail)
	}

	inst.mu.Lock()
	inst.lines = append(inst.lines, rec)
	if len(inst.lines) > m.opts.Ring {
		inst.lines = inst.lines[len(inst.lines)-m.opts.Ring:]
	}
	inst.mu.Unlock()

	m.mu.Lock()
	for ch := range m.subs {
		select {
		case ch <- rec:
		default: // slow consumer: drop, never block the tunnel
		}
	}
	m.mu.Unlock()
}

// classifyLevel maps a bare line onto the vocabulary at
// node/logger/logger.go:13-19. A tool that classifies its own lines implements
// nodeLogger.LogLiner instead and this is never reached for it.
func classifyLevel(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "error"), strings.Contains(l, "denied"),
		strings.Contains(l, "mismatch"), strings.Contains(l, "failed"),
		strings.Contains(l, "refused"), strings.Contains(l, "cannot"):
		return string(nodeLogger.LogError)
	case strings.Contains(l, "warn"):
		return string(nodeLogger.LogWarning)
	}
	return string(nodeLogger.LogInfo)
}

// persistedTunnel is the on-disk shape. Secrets are written as keys with empty
// values: the NAMES travel, the values come back from the environment at
// restore, so no secret ever lands in a file (CONTRACT §2.1, the same standard
// as SINGBOX_QUOTA_SECRET).
type persistedTunnel struct {
	Spec  Spec  `json:"spec"`
	Ports Ports `json:"ports"`
}

func persistPath(dir, id string, side Side) string {
	return filepath.Join(dir, fmt.Sprintf("%s.tunnel.json", safeFileName(id+"-"+side.String())))
}

// safeDirName/safeFileName keep a wire-supplied tunnel_id inside Dir. Ids are
// already validated to [A-Za-z0-9._-]{1,128} by Validate; this is the belt to
// that braces.
func safeDirName(id string) string  { return strings.Map(sanitizeRune, id) }
func safeFileName(id string) string { return strings.Map(sanitizeRune, id) }

func sanitizeRune(r rune) rune {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return r
	case r == '.' || r == '_' || r == '-':
		return r
	}
	return '_'
}

func (m *Manager) persist(spec Spec, ports Ports) error {
	if m.opts.Dir == "" {
		return nil
	}
	out := persistedTunnel{Spec: spec.Clone(), Ports: ports}
	// Drop the resolved values and the framework's own keys: only the secret
	// NAMES and the tool's knobs belong on disk.
	for k := range out.Spec.Secrets {
		out.Spec.Secrets[k] = ""
	}
	delete(out.Spec.Params, ParamBinaryPath)
	delete(out.Spec.Params, ParamConfigDir)

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	path := persistPath(m.opts.Dir, spec.TunnelID, spec.Side)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (m *Manager) removePersist(id string, side Side) {
	if m.opts.Dir == "" {
		return
	}
	_ = os.Remove(persistPath(m.opts.Dir, id, side))
}

func readPersisted(path string) (persistedTunnel, error) {
	var rec persistedTunnel
	data, err := os.ReadFile(path)
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return rec, err
	}
	if err := rec.Spec.Validate(); err != nil {
		return rec, err
	}
	return rec, nil
}
