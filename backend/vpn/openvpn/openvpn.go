package openvpn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/pasarguard/node/backend"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	nodeLogger "github.com/pasarguard/node/logger"
)

const (
	openvpnExecutableEnv = "OPENVPN_EXECUTABLE_PATH"
	defaultOpenVPNPath   = "/usr/local/bin/openvpn"
	mgmtPasswordEnv      = "OPENVPN_MGMT_PASSWORD"
)

// mgmtStartupTimeout bounds how long New waits for the management interface to
// answer. That socket is created at the end of openvpn's init — after the
// config parses, the PKI loads and the tun device is claimed — so a reachable
// management interface is proof the server accepted the config. Without it a
// bad port or a missing /dev/net/tun surfaces only as a core that never
// authenticates anybody.
const (
	mgmtStartupTimeout      = 15 * time.Second
	mgmtStartupPollInterval = 200 * time.Millisecond
)

// StatsProvider is accounting-quota's implementation of GetStats: the nftables
// counter read, the one number the panel bills from (LEGACY-VPN.md 4b).
//
// It is a hook rather than a method this package defines because stats.go,
// quota.go and nft.go belong to that agent (batch 5a-1 file ownership). Until
// it is installed, GetStats returns an empty response and says so once — an
// error would mark the whole node BROKEN on the panel's health check.
type StatsProvider func(ctx context.Context, req *common.StatRequest) (*common.StatResponse, error)

// OpenVPN implements backend.Backend for the OpenVPN core.
//
// Design notes that are not obvious from the code:
//
//   - A user change does not restart the child. The auth executable re-reads
//     the credential file on every login and openvpn re-reads a CCD file on
//     every connect, so a roster edit is a file write plus a kill of the
//     sessions that went away. That is the whole reason the seam is a file
//     instead of a config block — hysteria has no such file and restarts
//     (backend/hysteria/hysteria.go:38-40).
//   - Byte counts come from the nft counter, not from `status 2`. status 2 is
//     per-session and would restart at every reconnect; it is used for
//     liveness, the session list and `kill` only (LEGACY-VPN.md 4b).
//   - There is no second listener, so the apiPort+1 quota rule (CONTRACT 1.4)
//     does not apply: Ports is accepted and held, exactly as hysteria holds
//     MetricPort, so a future listener cannot collide with this core.
type OpenVPN struct {
	cfg     *Config
	nodeCfg *config.Config
	core    *Core
	mgmt    *Management

	dir     string
	exe     string
	authExe string

	users []*common.User
	ips   map[string]string

	mu         sync.RWMutex
	syncMu     sync.Mutex
	restarting bool
	idle       bool

	stats       StatsProvider
	statsWarned bool
}

// New builds and starts one OpenVPN core instance.
func New(ctx context.Context, cfg *Config, users []*common.User, ports backend.Ports, nodeCfg *config.Config) (*OpenVPN, error) {
	if cfg == nil {
		return nil, errors.New("openvpn config must not be nil")
	}
	if nodeCfg == nil || nodeCfg.GeneratedConfigPath == "" {
		return nil, errors.New("openvpn: generated config path is not set")
	}
	// ports is accepted for the CONTRACT 1.4 "held for the core's lifetime"
	// guarantee and deliberately unused: openvpn has no API or metrics listener.
	_ = ports

	dir, err := filepath.Abs(nodeCfg.GeneratedConfigPath)
	if err != nil {
		return nil, err
	}
	if err := ensurePKI(dir); err != nil {
		return nil, err
	}

	password, err := managementPassword(dir)
	if err != nil {
		return nil, err
	}

	exe, err := filepath.Abs(openvpnPath(nodeCfg))
	if err != nil {
		return nil, err
	}
	core, err := NewCore(exe, dir, nodeCfg.LogBufferSize, nodeCfg.StartupLogTailSize)
	if err != nil {
		return nil, err
	}
	core.SetLogger(nodeCfg.Debug)
	core.env = []string{credentialsEnv + "=" + filepath.Join(dir, credentialsFile)}

	authExe, err := filepath.Abs(authExecutable())
	if err != nil {
		return nil, err
	}

	socket := filepath.Join(dir, mgmtSocketFile)
	passwordFile := filepath.Join(dir, mgmtPasswordFile)
	text := cfg.Render(RenderOptions{
		AuthExecutable:         authExe,
		ManagementSocket:       socket,
		ManagementPasswordFile: passwordFile,
		ClientConfigDir:        ccdDir,
	})
	if err := writeServerConfig(dir, text); err != nil {
		return nil, err
	}

	o := &OpenVPN{
		cfg:     cfg,
		nodeCfg: nodeCfg,
		core:    core,
		dir:     dir,
		exe:     exe,
		authExe: authExe,
		mgmt:    newManagement(socket, password),
	}

	pairs, ips, err := o.roster(users)
	if err != nil {
		return nil, err
	}
	if err := syncRoster(dir, pairs, ips, cfg.Netmask); err != nil {
		return nil, err
	}
	o.users = users
	o.ips = ips

	// Idle-when-no-users: the same reason hysteria does not spawn the child
	// (backend/hysteria/hysteria.go:137) — there is nothing to authenticate,
	// and Started() answers true with uptime 0 so the panel health check stays
	// green instead of arming a Start-retry loop.
	if len(pairs) == 0 {
		o.idle = true
		logf("openvpn core idle: no eligible users; will start on the first user sync")
		return o, nil
	}

	// Prove the auth path before serving: a roster the executable cannot read
	// is otherwise discovered at a user's first login, in production.
	if err := o.selfCheckAuth(ctx, pairs[0]); err != nil {
		return nil, err
	}

	if err := core.Start(); err != nil {
		return nil, err
	}
	if err := o.checkStatus(ctx); err != nil {
		o.Shutdown()
		return nil, err
	}
	core.SwitchToRuntimeLogPhase()
	logf("openvpn started, Version: %s", o.Version())
	return o, nil
}

// selfCheckAuth runs the same executable openvpn will run, against the same
// credential file, bounded by authTimeout.
func (o *OpenVPN) selfCheckAuth(ctx context.Context, attempt credentialPair) error {
	actx, cancel := context.WithTimeout(ctx, authTimeout)
	defer cancel()
	return verifyWithAuthExecutable(actx, o.authExe, o.dir, attempt)
}

// managementPassword returns the management password and writes it where
// openvpn will read it: first line of a 0600 file, the `pw-file` half of
// `management <path> unix <pw-file>`.
//
// An operator may pin it with OPENVPN_MGMT_PASSWORD the same way
// SINGBOX_QUOTA_SECRET pins that core's; otherwise a fresh 32-byte value is
// generated per core per start. Either way it is written to the file, never put
// in the config, never logged and never returned — the secret-hygiene test
// greps the whole generated directory for it.
func managementPassword(dir string) (string, error) {
	password := config.GetEnv(mgmtPasswordEnv, "")
	if password == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("could not generate an openvpn management password: %w", err)
		}
		password = hex.EncodeToString(buf)
	}
	path := filepath.Join(dir, mgmtPasswordFile)
	if err := writeSecret(path, []byte(password+"\n")); err != nil {
		return "", fmt.Errorf("openvpn: writing %s: %w", mgmtPasswordFile, err)
	}
	return password, nil
}

// openvpnPath resolves the binary for this core. Read through config.GetEnv
// rather than a config.Config field because node/config/config.go belongs to
// core-runtime and this batch may not edit it.
func openvpnPath(cfg *config.Config) string {
	if cfg != nil {
		if custom := config.GetEnv(openvpnExecutableEnv, ""); custom != "" {
			return custom
		}
	}
	return defaultOpenVPNPath
}

// checkStatus blocks until the management interface answers, or gives up.
func (o *OpenVPN) checkStatus(ctx context.Context) error {
	deadline := time.Now().Add(mgmtStartupTimeout)
	ticker := time.NewTicker(mgmtStartupPollInterval)
	defer ticker.Stop()

	var lastErr error
	for {
		if !o.core.Started() {
			return fmt.Errorf("openvpn exited during startup: %s", o.startupFailureText())
		}
		if _, err := o.mgmt.Exec(ctx, "echo ok"); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("openvpn management interface never came up: %w (last: %s)",
				lastErr, o.startupFailureText())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (o *OpenVPN) startupFailureText() string {
	if tail := o.core.StartupLogTail(5); len(tail) > 0 {
		return joinLines(tail)
	}
	return "no output"
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += " | "
		}
		out += l
	}
	return out
}

// startFromIdle starts the child for an idle core whose roster just became
// non-empty. Caller holds syncMu.
func (o *OpenVPN) startFromIdle(ctx context.Context) error {
	pairs, _, err := o.roster(o.users)
	if err != nil {
		return err
	}
	if len(pairs) == 0 {
		return nil
	}
	if err := o.selfCheckAuth(ctx, pairs[0]); err != nil {
		return err
	}
	if err := o.core.Restart(); err != nil {
		return err
	}
	o.mu.Lock()
	o.idle = false
	o.mu.Unlock()

	checkCtx, cancel := context.WithTimeout(ctx, mgmtStartupTimeout)
	defer cancel()
	if err := o.checkStatus(checkCtx); err != nil {
		return err
	}
	o.core.SwitchToRuntimeLogPhase()
	logf("openvpn core started from idle (%d users)", len(pairs))
	return nil
}

func (o *OpenVPN) isIdle() bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.idle
}

func (o *OpenVPN) setIdle(v bool) {
	o.mu.Lock()
	o.idle = v
	o.mu.Unlock()
}

// Management is the seam accounting-quota drives: `kill` and the session list.
// nil while the core has never started.
func (o *OpenVPN) Management() *Management {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.mgmt
}

// AssignedIPs is the other half of that seam: the per-user tunnel address the
// nftables counter and the quota rules bind to (LEGACY-VPN.md 4b). A copy, so
// a caller cannot mutate the table the running core was built from.
func (o *OpenVPN) AssignedIPs() map[string]string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make(map[string]string, len(o.ips))
	for k, v := range o.ips {
		out[k] = v
	}
	return out
}

// SetStatsProvider installs accounting-quota's nft-backed GetStats. Called by
// that package's init or constructor; a second call replaces the first, which
// is what a test needs.
func (o *OpenVPN) SetStatsProvider(p StatsProvider) {
	o.mu.Lock()
	o.stats = p
	o.mu.Unlock()
}

// --- backend.Backend --------------------------------------------------------

// Started reports the core as up. An idle core answers true with uptime 0:
// it is a deliberate not-running, not a crash, and reporting false would keep
// the panel's health check red forever (the lesson backend/hysteria/hysteria.go
// :204-214 records).
func (o *OpenVPN) Started() bool {
	if o.isIdle() {
		return true
	}
	return o.core.Started()
}

func (o *OpenVPN) Version() string {
	if o.core == nil {
		return ""
	}
	return o.core.Version()
}

func (o *OpenVPN) Logs() <-chan string {
	if o.core == nil {
		return nil
	}
	return o.core.Logs()
}

// LogLines is the classified stream the GetLogs handlers prefer
// (node/logger.LogLiner).
func (o *OpenVPN) LogLines() <-chan nodeLogger.LogLine {
	if o.core == nil {
		return nil
	}
	return o.core.LogLines()
}

func (o *OpenVPN) Restart() error {
	if o.isIdle() {
		// Nothing to restart: the child is intentionally not running and the
		// current roster has no user to start for.
		return nil
	}
	o.mu.Lock()
	if o.restarting {
		o.mu.Unlock()
		return errors.New("openvpn is already restarting")
	}
	o.restarting = true
	o.mu.Unlock()

	// The management socket is recreated with the child: drop the old handle
	// first or every later command talks to an inode nobody listens on.
	o.mgmt.Close()
	err := o.core.Restart()

	o.mu.Lock()
	o.restarting = false
	o.mu.Unlock()

	if err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(context.Background(), mgmtStartupTimeout)
	defer cancel()
	return o.checkStatus(checkCtx)
}

func (o *OpenVPN) Shutdown() {
	if o.mgmt != nil {
		o.mgmt.Close()
	}
	if o.core != nil {
		o.core.Stop()
	}
}

func (o *OpenVPN) SyncUser(ctx context.Context, user *common.User) error {
	if user.GetEmail() == "" {
		return errors.New("email is required")
	}
	return o.applyUsers(ctx, []*common.User{user}, false)
}

func (o *OpenVPN) SyncUsers(ctx context.Context, users []*common.User) error {
	return o.applyUsers(ctx, users, true)
}

func (o *OpenVPN) UpdateUsers(ctx context.Context, users []*common.User) error {
	return o.applyUsers(ctx, users, false)
}

// UpdateUsersAndRestart is the same work: a roster edit is already a file
// write plus the kills of the sessions that went away, and there is no config
// block to rewrite.
func (o *OpenVPN) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	return o.applyUsers(ctx, users, false)
}

// GetSysStats reports the child's uptime and zeroes the Go runtime counters.
// openvpn is a separate process, so the node's heap and GC numbers would be a
// property of a program this code does not own; only Uptime is meaningful, and
// an error here would mark a healthy node BROKEN on the panel's health check
// (the same reasoning as backend/hysteria/stats_backend.go:13-33).
func (o *OpenVPN) GetSysStats(_ context.Context) (*common.BackendStatsResponse, error) {
	var uptime time.Duration
	if !o.isIdle() && o.core != nil {
		uptime = o.core.Uptime()
	}
	return &common.BackendStatsResponse{Uptime: uint32(uptime.Seconds())}, nil
}

// GetStats delegates to accounting-quota's counter reader when it is wired.
//
// Until then: an empty response, not an error. record_usages treats an error
// from one core as a node health failure, and returning `status 2` byte counts
// instead would bill per-session numbers that reset at every reconnect —
// explicitly rejected by LEGACY-VPN.md 4b.
func (o *OpenVPN) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	o.mu.RLock()
	provider := o.stats
	warned := o.statsWarned
	if !warned {
		o.statsWarned = true
	}
	o.mu.RUnlock()

	if provider != nil {
		return provider(ctx, request)
	}
	if !warned {
		logf("openvpn: no StatsProvider installed — traffic counters are reported as zero until accounting-quota wires nft.go")
	}
	return &common.StatResponse{}, nil
}

// GetOutboundsLatency: latency probing is an xray observatory feature.
// openvpn has no outbound concept.
func (o *OpenVPN) GetOutboundsLatency(_ context.Context, _ *common.LatencyRequest) (*common.LatencyResponse, error) {
	return nil, errors.New("outbound latency is not supported by the openvpn backend")
}

// GetUserOnlineStats reads the session list off the management interface:
// 0 or 1 connected instance per common name.
func (o *OpenVPN) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	if o.isIdle() {
		return &common.OnlineStatResponse{Name: email, Value: 0}, nil
	}
	m := o.Management()
	if m == nil {
		return &common.OnlineStatResponse{Name: email, Value: 0}, nil
	}
	sessions, err := m.Sessions(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok := sessions[email]; !ok {
		return &common.OnlineStatResponse{Name: email, Value: 0}, nil
	}
	return &common.OnlineStatResponse{Name: email, Value: 1}, nil
}

// GetUserOnlineIpListStats reports the tunnel address a user is online from —
// the same address the CCD file pinned and the accounting rules match on.
func (o *OpenVPN) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	out := &common.StatsOnlineIpListResponse{Name: email, Ips: map[string]int64{}}
	if o.isIdle() {
		return out, nil
	}
	m := o.Management()
	if m == nil {
		return out, nil
	}
	sessions, err := m.Sessions(ctx)
	if err != nil {
		return nil, err
	}
	if s, ok := sessions[email]; ok && s.VirtualAddr != "" {
		out.Ips[s.VirtualAddr] = 1
	}
	return out, nil
}
