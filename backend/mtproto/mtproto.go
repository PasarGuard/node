package mtproto

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	gopsutilprocess "github.com/shirou/gopsutil/v4/process"

	"github.com/pasarguard/node/common"
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

func (m *MTProto) GetSysStats(_ context.Context) (*common.BackendStatsResponse, error) {
	if !m.process.Started() {
		return nil, errors.New("mtproto backend is not started")
	}

	pid := m.process.PID()
	if pid == 0 {
		return nil, errors.New("telemt process pid is unavailable")
	}

	process, err := gopsutilprocess.NewProcess(int32(pid))
	if err != nil {
		return nil, err
	}

	result := &common.BackendStatsResponse{}
	if memoryInfo, err := process.MemoryInfo(); err == nil && memoryInfo != nil {
		result.Alloc = memoryInfo.RSS
		result.Sys = memoryInfo.VMS
	}

	if createTimeMillis, err := process.CreateTime(); err == nil && createTimeMillis > 0 {
		uptimeSeconds := uint64(0)
		nowMillis := time.Now().UnixMilli()
		if nowMillis > createTimeMillis {
			uptimeSeconds = uint64((nowMillis - createTimeMillis) / 1000)
		}
		if uptimeSeconds > uint64(^uint32(0)) {
			uptimeSeconds = uint64(^uint32(0))
		}
		result.Uptime = uint32(uptimeSeconds)
	}

	return result, nil
}

func (m *MTProto) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	if !m.process.Started() {
		return nil, errors.New("mtproto backend is not started")
	}

	// telemt binds metrics together with its API, after the Telegram DC
	// check. Treat a scrape miss (telemt restarting, say) as empty stats
	// rather than failing the panel poll.
	if err := m.refreshTracker(ctx); err != nil {
		return &common.StatResponse{Stats: []*common.Stat{}}, nil
	}

	link := m.config.InboundTag
	switch request.GetType() {
	case common.StatType_UsersStat:
		return m.tracker.UsersStats(link, request.GetReset_()), nil
	case common.StatType_UserStat:
		return m.tracker.UserStats(request.GetName(), link, request.GetReset_()), nil
	case common.StatType_Outbounds, common.StatType_Outbound:
		if request.GetType() == common.StatType_Outbound && request.GetName() != "" && request.GetName() != link {
			return &common.StatResponse{Stats: []*common.Stat{}}, nil
		}
		return m.tracker.AggregateStats(link, "mtproto", request.GetReset_()), nil
	case common.StatType_Inbounds, common.StatType_Inbound:
		if request.GetType() == common.StatType_Inbound && request.GetName() != "" && request.GetName() != link {
			return &common.StatResponse{Stats: []*common.Stat{}}, nil
		}
		return m.tracker.AggregateStats(link, link, request.GetReset_()), nil
	default:
		return nil, errors.New("unsupported mtproto stat type")
	}
}

// GetOutboundsLatency is not applicable to an MTProto proxy (no outbounds);
// it returns an empty result to satisfy the backend.Backend interface.
func (m *MTProto) GetOutboundsLatency(_ context.Context, _ *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
}

func (m *MTProto) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	if !m.process.Started() {
		return nil, errors.New("mtproto backend is not started")
	}

	if !m.isDesiredUser(email) {
		return &common.OnlineStatResponse{Name: email, Value: 0}, nil
	}

	// Online count comes from telemt's per-user gauge (telemt_user_connections_current)
	// via the metrics scrape, rather than a per-user API call.
	snapshot, err := m.metricsScraper.Scrape(ctx)
	if err != nil {
		return &common.OnlineStatResponse{Name: email, Value: 0}, nil
	}

	return &common.OnlineStatResponse{
		Name:  email,
		Value: snapshot[email].ConnectionsCurrent,
	}, nil
}

func (m *MTProto) GetUserOnlineIpListStats(ctx context.Context, email string) (*common.StatsOnlineIpListResponse, error) {
	if !m.process.Started() {
		return nil, errors.New("mtproto backend is not started")
	}

	response := &common.StatsOnlineIpListResponse{
		Name: email,
		Ips:  make(map[string]int64),
	}

	if !m.isDesiredUser(email) {
		return response, nil
	}

	// The active-IP list is only available from the API (metrics expose the
	// count only). A read of one user loads telemt's whole config, so this
	// takes the list of every user in one call.
	activeIPs, err := m.apiClient.ActiveIPs(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	for _, ip := range activeIPs[email] {
		if ip == "" {
			continue
		}
		response.Ips[ip] = now
	}

	return response, nil
}

func (m *MTProto) refreshTracker(ctx context.Context) error {
	m.stateMu.RLock()
	activeUsers := make(map[string]struct{}, len(m.desired))
	for username := range m.desired {
		activeUsers[username] = struct{}{}
	}
	scraper := m.metricsScraper
	tracker := m.tracker
	m.stateMu.RUnlock()

	snapshot, err := scraper.Scrape(ctx)
	if err != nil {
		return fmt.Errorf("failed to scrape telemt metrics: %w", err)
	}

	tracker.Sync(snapshot, activeUsers)
	return nil
}

func (m *MTProto) isDesiredUser(username string) bool {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	_, exists := m.desired[username]
	return exists
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
