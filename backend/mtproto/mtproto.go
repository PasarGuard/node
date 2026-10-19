package mtproto

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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
	sentinel       *runtimeUser

	apiPort       int
	metricsPort   int
	apiAuthHeader string

	// syncMu serializes every operation that changes users or the telemt
	// process: syncs, restarts, the supervisor and Shutdown.
	syncMu sync.Mutex
	closed bool // guarded by syncMu

	// mu guards desired for readers; writers also hold syncMu.
	mu      sync.RWMutex
	desired map[string]*runtimeUser

	// lifetime is cancelled by Shutdown so waits for telemt stop early.
	lifetime       context.Context
	cancel         context.CancelFunc
	supervisorDone chan struct{}
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
	return m.startLocked(m.lifetime)
}

func (m *MTProto) SyncUser(ctx context.Context, user *common.User) error {
	// The batch paths skip a user that fails validation; a single-user sync
	// reports it to the caller instead.
	if _, _, err := activeUserFromCommon(user, m.config.InboundTag); err != nil {
		return err
	}
	return m.updateUsersPartial(ctx, []*common.User{user})
}

func (m *MTProto) SyncUsers(ctx context.Context, users []*common.User) error {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	if m.closed {
		return errClosed
	}
	desired, _ := ActiveUsersFromCommon(users, m.config.InboundTag)

	return m.applyFullDesiredLocked(ctx, desired)
}

func (m *MTProto) UpdateUsers(ctx context.Context, users []*common.User) error {
	return m.updateUsersPartial(ctx, users)
}

func (m *MTProto) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	if m.closed {
		return errClosed
	}
	nextDesired := m.buildNextDesiredLocked(users)

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
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	if m.closed {
		return errClosed
	}
	nextDesired := m.buildNextDesiredLocked(users)

	if len(m.desired) == 0 || len(nextDesired) == 0 {
		return m.applyFullDesiredLocked(ctx, nextDesired)
	}

	if err := m.applyPartialDesiredLocked(ctx, users, nextDesired); err != nil {
		return m.applyFullDesiredLocked(ctx, nextDesired)
	}

	m.setDesiredLocked(nextDesired)
	return nil
}

// buildNextDesiredLocked applies users on top of m.desired. A user that fails
// validation is logged and treated as not included, like an untagged one.
func (m *MTProto) buildNextDesiredLocked(users []*common.User) map[string]*runtimeUser {
	nextDesired := cloneRuntimeUserMap(m.desired)
	for _, user := range users {
		if user == nil {
			continue
		}

		username := strings.TrimSpace(user.GetEmail())
		runtimeUser, include, err := activeUserFromCommon(user, m.config.InboundTag)
		if err != nil {
			logSkippedUser(username, err)
		}
		if include {
			nextDesired[runtimeUser.Username] = runtimeUser
			continue
		}
		delete(nextDesired, username)
	}
	return nextDesired
}

func (m *MTProto) applyPartialDesiredLocked(ctx context.Context, users []*common.User, nextDesired map[string]*runtimeUser) error {
	for _, user := range users {
		if user == nil {
			continue
		}

		// An invalid user (already logged by buildNextDesiredLocked) is
		// removed like an untagged one.
		runtimeUser, include, err := activeUserFromCommon(user, m.config.InboundTag)
		if err == nil && include {
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
		if err := m.startLocked(ctx); err != nil {
			return err
		}
	} else if err := m.reloadLocked(ctx); err != nil {
		return err
	}

	if err := m.waitForRuntimeUsers(ctx, previousDesired, desired); err != nil {
		return err
	}

	m.setDesiredLocked(desired)
	return nil
}

// reloadLocked makes the running telemt re-read the rendered config and
// restarts it when the reload fails. Requires syncMu.
func (m *MTProto) reloadLocked(ctx context.Context) error {
	err := m.process.Reload()
	if err == nil {
		err = m.waitForHealth(ctx)
	}
	if err == nil || errors.Is(err, errClosed) {
		return err
	}

	log.Printf("telemt reload failed, restarting it: %v", err)
	m.process.Stop()
	if restartErr := m.startLocked(ctx); restartErr != nil {
		return fmt.Errorf("telemt reload failed: %w (restart failed: %v)", err, restartErr)
	}
	return nil
}

// setDesiredLocked replaces the desired users. Requires syncMu.
func (m *MTProto) setDesiredLocked(desired map[string]*runtimeUser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.desired = cloneRuntimeUserMap(desired)
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

	return writeFileAtomic(m.configPath, []byte(rendered))
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
		case <-m.lifetime.Done():
			return errClosed
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
