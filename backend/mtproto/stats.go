package mtproto

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"math"
	"strings"
	"time"

	gopsutilprocess "github.com/shirou/gopsutil/v4/process"

	"github.com/pasarguard/node/common"
)

const (
	// statsSnapshotMaxAge is how long one refresh serves later readers. The
	// panel's user, node and online polls often arrive together, and in
	// API-totals mode each refresh makes telemt load its whole config.
	statsSnapshotMaxAge = time.Second
	// refreshErrorLogInterval is the least time between two logged refresh
	// failures.
	refreshErrorLogInterval = time.Minute
	// refreshFailedMessage starts the log line of a failed refresh.
	refreshFailedMessage = "warning: mtproto: failed to read telemt traffic counters"
)

// refreshState is the outcome of the latest stats refresh. Guarded by
// MTProto.refreshMu.
type refreshState struct {
	at       time.Time
	snapshot trafficSnapshot
	err      error
	// loggedAt is when a failure was last logged, and unlogged how many
	// failures came after it.
	loggedAt time.Time
	unlogged int
}

func (m *MTProto) GetStats(ctx context.Context, request *common.StatRequest) (*common.StatResponse, error) {
	if !m.process.Started() {
		return nil, errors.New("mtproto backend is not started")
	}

	// A failed read (telemt restarting, say) answers empty rather than
	// failing the panel poll. The tracker keeps the unreported traffic for
	// the next read that works.
	if _, err := m.refreshStats(ctx); err != nil {
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
		return m.tracker.AggregateStats(familyOutbound, link, "mtproto", request.GetReset_()), nil
	case common.StatType_Inbounds, common.StatType_Inbound:
		if request.GetType() == common.StatType_Inbound && request.GetName() != "" && request.GetName() != link {
			return &common.StatResponse{Stats: []*common.Stat{}}, nil
		}
		return m.tracker.AggregateStats(familyInbound, link, link, request.GetReset_()), nil
	default:
		return nil, errors.New("unsupported mtproto stat type")
	}
}

// GetUserOnlineStats returns the user's distinct client IPs, as xray does:
// one Telegram client opens several connections.
func (m *MTProto) GetUserOnlineStats(ctx context.Context, email string) (*common.OnlineStatResponse, error) {
	if !m.process.Started() {
		return nil, errors.New("mtproto backend is not started")
	}

	response := &common.OnlineStatResponse{Name: email}
	if !m.isDesiredUser(email) {
		return response, nil
	}
	snapshot, err := m.refreshStats(ctx)
	if err != nil {
		return response, nil
	}
	response.Value = snapshot.Users[email].UniqueIPsCurrent
	return response, nil
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

// GetOutboundsLatency is not applicable to an MTProto proxy (no outbounds);
// it returns an empty result to satisfy the backend.Backend interface.
func (m *MTProto) GetOutboundsLatency(_ context.Context, _ *common.LatencyRequest) (*common.LatencyResponse, error) {
	return &common.LatencyResponse{Latencies: []*common.Latency{}}, nil
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

// refreshStats reads telemt's per-user counters and applies them to the
// tracker. Refreshes are serialized, so snapshots reach the tracker in the
// order telemt produced them, and callers within statsSnapshotMaxAge of the
// last refresh share its outcome. It never takes syncMu.
func (m *MTProto) refreshStats(ctx context.Context) (trafficSnapshot, error) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()

	if !m.refresh.at.IsZero() && m.statsNow().Sub(m.refresh.at) < statsSnapshotMaxAge {
		return m.refresh.snapshot, m.refresh.err
	}

	snapshot, err := m.readTraffic(ctx)
	// Stamped after the read, so callers queued behind a slow one share it.
	now := m.statsNow()
	if err != nil {
		if ctx.Err() != nil {
			// The caller gave up; the next one tries again.
			return trafficSnapshot{}, err
		}
		m.logRefreshErrorLocked(now, err)
		m.refresh.at, m.refresh.snapshot, m.refresh.err = now, trafficSnapshot{}, err
		return trafficSnapshot{}, err
	}

	m.tracker.Apply(snapshot)
	m.refresh.at, m.refresh.snapshot, m.refresh.err = now, snapshot, nil
	return snapshot, nil
}

// readTraffic takes one snapshot of telemt's per-user counters, without
// marker users. It reads the metrics endpoint, and the user list only while
// telemt suppresses per-user series: telemt loads and parses its whole
// config file for that list.
func (m *MTProto) readTraffic(ctx context.Context) (trafficSnapshot, error) {
	generation := m.process.Generation()

	users, suppressed, err := m.metricsScraper.Scrape(ctx)
	if err != nil {
		return trafficSnapshot{}, fmt.Errorf("failed to scrape telemt metrics: %w", err)
	}
	source := sourceMetrics
	if suppressed > 0 {
		listed, err := m.apiClient.ListUsers(ctx)
		if err != nil {
			return trafficSnapshot{}, fmt.Errorf("telemt suppresses per-user metrics and listing its users failed: %w", err)
		}
		users = usersFromAPI(listed)
		source = sourceAPITotals
	}

	// A telemt started during the read may have answered instead of the
	// one it began with; its counters cannot be told apart.
	if m.process.Generation() != generation {
		return trafficSnapshot{}, errors.New("telemt restarted while its counters were read")
	}

	maps.DeleteFunc(users, func(username string, _ userMetrics) bool {
		return strings.HasPrefix(username, markerUsernamePrefix)
	})
	return trafficSnapshot{Users: users, Source: source, Generation: generation}, nil
}

// usersFromAPI maps telemt's user list to per-user metrics: total_octets
// (both directions summed) as downlink.
func usersFromAPI(listed []telemtUserInfo) map[string]userMetrics {
	users := make(map[string]userMetrics, len(listed))
	for _, user := range listed {
		users[user.Username] = userMetrics{
			Downlink:           int64(min(user.TotalOctets, math.MaxInt64)),
			ConnectionsCurrent: int64(min(user.CurrentConnections, math.MaxInt64)),
			UniqueIPsCurrent:   int64(user.ActiveUniqueIPs),
		}
	}
	return users
}

// logRefreshErrorLocked logs a failed refresh at most once per
// refreshErrorLogInterval. Requires refreshMu.
func (m *MTProto) logRefreshErrorLocked(now time.Time, err error) {
	if !m.refresh.loggedAt.IsZero() && now.Sub(m.refresh.loggedAt) < refreshErrorLogInterval {
		m.refresh.unlogged++
		return
	}
	suffix := ""
	if m.refresh.unlogged > 0 {
		suffix = fmt.Sprintf(" (%d more failures since the last report)", m.refresh.unlogged)
	}
	log.Printf("%s; usage is kept and reported once a read works%s: %v", refreshFailedMessage, suffix, err)
	m.refresh.loggedAt = now
	m.refresh.unlogged = 0
}

func (m *MTProto) statsNow() time.Time {
	if m.statsClock != nil {
		return m.statsClock()
	}
	return time.Now()
}

func (m *MTProto) isDesiredUser(username string) bool {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	_, exists := m.desired[username]
	return exists
}
