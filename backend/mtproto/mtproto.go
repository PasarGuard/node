package mtproto

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gopsutilprocess "github.com/shirou/gopsutil/v4/process"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
)

const (
	telemtStartupTimeout = 30 * time.Second
)

type MTProto struct {
	cfg            *config.Config
	config         *Config
	process        *processManager
	apiClient      *apiClient
	metricsScraper *metricsScraper
	tracker        *trafficTracker
	sentinel       *runtimeUser

	apiPort       int
	metricsPort   int
	apiAuthHeader string

	mu           sync.RWMutex
	desired      map[string]*runtimeUser
	shutdownOnce sync.Once
}

func New(ctx context.Context, cfg *config.Config, mtConfig *Config, users []*common.User) (*MTProto, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	if mtConfig == nil {
		return nil, errors.New("mtproto config is nil")
	}

	apiPort := netutil.FindFreePort()
	metricsPort := netutil.FindFreePort()
	for metricsPort == apiPort {
		metricsPort = netutil.FindFreePort()
	}

	authHeader, err := generateBearerToken()
	if err != nil {
		return nil, err
	}

	generatedRoot, err := filepath.Abs(cfg.GeneratedConfigPath)
	if err != nil {
		return nil, err
	}
	telemtDir := filepath.Join(generatedRoot, "telemt")
	process, err := newProcessManager(
		cfg.TelemtExecutablePath,
		filepath.Join(telemtDir, "config.toml"),
		filepath.Join(telemtDir, "telemt.pid"),
		cfg.LogBufferSize,
	)
	if err != nil {
		return nil, err
	}

	activeUsers, err := ActiveUsersFromCommon(users, mtConfig.InboundTag)
	if err != nil {
		return nil, err
	}

	sentinel, err := newSentinelUser()
	if err != nil {
		return nil, err
	}

	mt := &MTProto{
		cfg:            cfg,
		config:         mtConfig,
		process:        process,
		apiClient:      newAPIClient(fmt.Sprintf("http://127.0.0.1:%d", apiPort), authHeader),
		metricsScraper: newMetricsScraper(fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort)),
		tracker:        newTrafficTracker(),
		sentinel:       sentinel,
		apiPort:        apiPort,
		metricsPort:    metricsPort,
		apiAuthHeader:  authHeader,
		desired:        cloneRuntimeUserMap(activeUsers),
	}

	if err := mt.writeRenderedConfigLocked(mt.desired); err != nil {
		return nil, err
	}
	if err := mt.process.Start(); err != nil {
		return nil, err
	}
	if err := mt.waitForHealth(ctx); err != nil {
		mt.Shutdown()
		return nil, err
	}

	return mt, nil
}

func (m *MTProto) Started() bool {
	return m.process.Started()
}

func (m *MTProto) Version() string {
	return m.process.Version()
}

func (m *MTProto) Logs() <-chan string {
	return m.process.Logs()
}

func (m *MTProto) Restart() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.writeRenderedConfigLocked(m.desired); err != nil {
		return err
	}
	if err := m.process.Restart(); err != nil {
		return err
	}

	return m.waitForHealth(context.Background())
}

func (m *MTProto) Shutdown() {
	m.shutdownOnce.Do(func() {
		m.process.Shutdown()
		m.process.CloseLogs()
	})
}

func (m *MTProto) SyncUser(ctx context.Context, user *common.User) error {
	return m.updateUsersPartial(ctx, []*common.User{user})
}

func (m *MTProto) SyncUsers(ctx context.Context, users []*common.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	desired, err := ActiveUsersFromCommon(users, m.config.InboundTag)
	if err != nil {
		return err
	}

	return m.applyFullDesiredLocked(ctx, desired)
}

func (m *MTProto) UpdateUsers(ctx context.Context, users []*common.User) error {
	return m.updateUsersPartial(ctx, users)
}

func (m *MTProto) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	nextDesired, err := m.buildNextDesiredLocked(users)
	if err != nil {
		return err
	}

	return m.applyFullDesiredLocked(ctx, nextDesired)
}

func (m *MTProto) GetSysStats(_ context.Context) (*common.BackendStatsResponse, error) {
	if !m.process.Started() {
		return nil, errors.New("mtproto backend is not started")
	}

	pid := m.process.PID()
	if pid == 0 {
		return nil, errors.New("telemt process pid is unavailable")
	}

	process, err := gopsutilprocess.NewProcess(pid)
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

	if err := m.refreshTracker(ctx); err != nil {
		return nil, err
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
		return nil, fmt.Errorf("failed to scrape telemt metrics: %w", err)
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

	// The active-IP *list* is only available from the API (metrics expose the count only).
	userInfo, err := m.apiClient.GetUser(ctx, email)
	if err != nil {
		var apiErr *apiStatusError
		if errors.As(err, &apiErr) && apiErr.NotFound() {
			return response, nil
		}
		return nil, err
	}

	now := time.Now().Unix()
	for _, ip := range userInfo.ActiveUniqueIPsList {
		if ip == "" {
			continue
		}
		response.Ips[ip] = now
	}

	return response, nil
}

func (m *MTProto) updateUsersPartial(ctx context.Context, users []*common.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	nextDesired, err := m.buildNextDesiredLocked(users)
	if err != nil {
		return err
	}

	if len(m.desired) == 0 || len(nextDesired) == 0 {
		return m.applyFullDesiredLocked(ctx, nextDesired)
	}

	if err := m.applyPartialDesiredLocked(ctx, users, nextDesired); err != nil {
		return m.applyFullDesiredLocked(ctx, nextDesired)
	}

	m.desired = cloneRuntimeUserMap(nextDesired)
	return nil
}

func (m *MTProto) buildNextDesiredLocked(users []*common.User) (map[string]*runtimeUser, error) {
	nextDesired := cloneRuntimeUserMap(m.desired)
	for _, user := range users {
		runtimeUser, include, err := activeUserFromCommon(user, m.config.InboundTag)
		if err != nil {
			return nil, err
		}

		username := strings.TrimSpace(user.GetEmail())
		if include {
			nextDesired[runtimeUser.Username] = runtimeUser
			continue
		}
		delete(nextDesired, username)
	}
	return nextDesired, nil
}

func (m *MTProto) applyPartialDesiredLocked(ctx context.Context, users []*common.User, nextDesired map[string]*runtimeUser) error {
	for _, user := range users {
		runtimeUser, include, err := activeUserFromCommon(user, m.config.InboundTag)
		if err != nil {
			return err
		}

		if include {
			if err := m.upsertUser(ctx, runtimeUser); err != nil {
				return err
			}
			continue
		}

		username := strings.TrimSpace(user.GetEmail())
		if username == "" {
			continue
		}
		if err := m.deleteUser(ctx, username); err != nil {
			return err
		}
	}

	_ = nextDesired
	return nil
}

func (m *MTProto) upsertUser(ctx context.Context, user *runtimeUser) error {
	_, err := m.apiClient.GetUser(ctx, user.Username)
	if err == nil {
		return m.apiClient.PatchUser(ctx, user.Username, user)
	}

	var apiErr *apiStatusError
	if errors.As(err, &apiErr) && apiErr.NotFound() {
		return m.apiClient.CreateUser(ctx, user)
	}

	return err
}

func (m *MTProto) deleteUser(ctx context.Context, username string) error {
	err := m.apiClient.DeleteUser(ctx, username)
	if err == nil {
		return nil
	}

	var apiErr *apiStatusError
	if errors.As(err, &apiErr) && apiErr.NotFound() {
		return nil
	}
	return err
}

func (m *MTProto) applyFullDesiredLocked(ctx context.Context, desired map[string]*runtimeUser) error {
	previousDesired := cloneRuntimeUserMap(m.desired)

	if err := m.writeRenderedConfigLocked(desired); err != nil {
		return err
	}

	if !m.process.Started() {
		if err := m.process.Start(); err != nil {
			return err
		}
		if err := m.waitForHealth(ctx); err != nil {
			m.process.Shutdown()
			return err
		}
		if err := m.waitForRuntimeUsers(ctx, previousDesired, desired); err != nil {
			return err
		}
		m.desired = cloneRuntimeUserMap(desired)
		return nil
	}

	if err := m.process.Reload(); err != nil {
		if restartErr := m.process.Restart(); restartErr != nil {
			return fmt.Errorf("telemt reload failed: %w (restart failed: %v)", err, restartErr)
		}
		if healthErr := m.waitForHealth(ctx); healthErr != nil {
			return healthErr
		}
		if runtimeErr := m.waitForRuntimeUsers(ctx, previousDesired, desired); runtimeErr != nil {
			return runtimeErr
		}
		m.desired = cloneRuntimeUserMap(desired)
		return nil
	}

	if err := m.waitForHealth(ctx); err != nil {
		if restartErr := m.process.Restart(); restartErr != nil {
			return fmt.Errorf("telemt reload health check failed: %w (restart failed: %v)", err, restartErr)
		}
		if healthErr := m.waitForHealth(ctx); healthErr != nil {
			return healthErr
		}
	}
	if err := m.waitForRuntimeUsers(ctx, previousDesired, desired); err != nil {
		return err
	}

	m.desired = cloneRuntimeUserMap(desired)
	return nil
}

func (m *MTProto) writeRenderedConfigLocked(desired map[string]*runtimeUser) error {
	var sentinel *runtimeUser
	if len(desired) == 0 {
		sentinel = m.sentinel
	}

	rendered, err := m.config.Render(desired, sentinel, m.apiPort, m.metricsPort, m.apiAuthHeader)
	if err != nil {
		return err
	}

	return writeFileAtomic(m.process.configPath, []byte(rendered))
}

func (m *MTProto) waitForHealth(ctx context.Context) error {
	waitContext := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		waitContext, cancel = context.WithTimeout(ctx, telemtStartupTimeout)
		defer cancel()
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	waitCh := m.process.WaitChan()

	for {
		if err := m.apiClient.Health(waitContext); err == nil {
			return nil
		}

		select {
		case <-waitContext.Done():
			return waitContext.Err()
		case err := <-waitCh:
			if err == nil {
				return errors.New("telemt process exited before becoming healthy")
			}
			return fmt.Errorf("telemt process exited before becoming healthy: %w", err)
		case <-ticker.C:
		}
	}
}

func (m *MTProto) waitForRuntimeUsers(ctx context.Context, previousDesired, desired map[string]*runtimeUser) error {
	waitContext := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		waitContext, cancel = context.WithTimeout(ctx, telemtStartupTimeout)
		defer cancel()
	}

	expectedPresent := make(map[string]struct{}, len(desired))
	for username := range desired {
		expectedPresent[username] = struct{}{}
	}
	if len(expectedPresent) == 0 {
		expectedPresent[m.sentinel.Username] = struct{}{}
	}

	expectedAbsent := make(map[string]struct{})
	for username := range previousDesired {
		if _, keep := desired[username]; !keep {
			expectedAbsent[username] = struct{}{}
		}
	}
	// Going from zero desired users to real users drops the sentinel, but it is
	// not in previousDesired, so require it to be gone explicitly.
	if len(previousDesired) == 0 && len(desired) > 0 {
		expectedAbsent[m.sentinel.Username] = struct{}{}
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		converged := true

		for username := range expectedPresent {
			if _, err := m.apiClient.GetUser(waitContext, username); err != nil {
				converged = false
				break
			}
		}

		if converged {
			for username := range expectedAbsent {
				_, err := m.apiClient.GetUser(waitContext, username)
				if err == nil {
					converged = false
					break
				}

				var apiErr *apiStatusError
				if !errors.As(err, &apiErr) || !apiErr.NotFound() {
					converged = false
					break
				}
			}
		}

		if converged {
			return nil
		}

		select {
		case <-waitContext.Done():
			return waitContext.Err()
		case <-ticker.C:
		}
	}
}

func (m *MTProto) refreshTracker(ctx context.Context) error {
	m.mu.RLock()
	activeUsers := make(map[string]struct{}, len(m.desired))
	for username := range m.desired {
		activeUsers[username] = struct{}{}
	}
	scraper := m.metricsScraper
	tracker := m.tracker
	m.mu.RUnlock()

	snapshot, err := scraper.Scrape(ctx)
	if err != nil {
		return fmt.Errorf("failed to scrape telemt metrics: %w", err)
	}

	tracker.Sync(snapshot, activeUsers)
	return nil
}

func (m *MTProto) isDesiredUser(username string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.desired[username]
	return exists
}

func newSentinelUser() (*runtimeUser, error) {
	secret := make([]byte, 16)
	usernameSuffix := make([]byte, 4)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate mtproto sentinel secret: %w", err)
	}
	if _, err := rand.Read(usernameSuffix); err != nil {
		return nil, fmt.Errorf("failed to generate mtproto sentinel username: %w", err)
	}

	return &runtimeUser{
		Username: "pg-node-internal-" + hex.EncodeToString(usernameSuffix),
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
	defer os.Remove(tempPath)

	if _, err := tempFile.Write(payload); err != nil {
		_ = tempFile.Close()
		return err
	}
	if err := tempFile.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
