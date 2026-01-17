package controller

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pasarguard/node/common"
)

// LimitEnforcerMetrics contains metrics for monitoring the limit enforcer
type LimitEnforcerMetrics struct {
	// Counters
	UsersRemoved    atomic.Int64 // Total users removed due to limit exceeded
	ChecksPerformed atomic.Int64 // Total limit checks performed
	CheckErrors     atomic.Int64 // Total errors during checks
	RefreshCount    atomic.Int64 // Total cache refreshes

	// Gauges (current values)
	TrackedUsers      atomic.Int64 // Current number of users being tracked
	CachedLimits      atomic.Int64 // Current number of limits in cache
	LastCheckDuration atomic.Int64 // Last check duration in milliseconds
	LastCheckTime     atomic.Int64 // Unix timestamp of last check
}

// userTrafficEntry tracks traffic data with last seen time for cleanup
type userTrafficEntry struct {
	traffic  int64
	lastSeen time.Time
}

// LimitEnforcer monitors user traffic and removes users who exceed their node-specific limits
type LimitEnforcer struct {
	controller    *Controller
	limitsCache   *common.TrafficLimitsCache
	checkInterval time.Duration
	stopChan      chan struct{}

	// Track cumulative traffic per user (since xray stats are reset on read)
	userTraffic map[int]*userTrafficEntry
	trafficMu   sync.RWMutex

	// Configuration for cleanup
	cleanupInterval time.Duration // How often to clean inactive users (default: 1h)
	inactiveTimeout time.Duration // Remove users not seen for this duration (default: 24h)

	// Metrics for monitoring
	Metrics LimitEnforcerMetrics
}

// LimitEnforcerConfig contains configuration for the limit enforcer
type LimitEnforcerConfig struct {
	NodeID          int
	PanelAPIURL     string
	APIKey          string
	CheckInterval   time.Duration // How often to check stats (default: 30s)
	RefreshInterval time.Duration // How often to refresh limits from panel (default: 60s)
	CleanupInterval time.Duration // How often to clean inactive users (default: 1h)
	InactiveTimeout time.Duration // Remove users not seen for this duration (default: 24h)
}

// NewLimitEnforcer creates a new limit enforcer
func NewLimitEnforcer(controller *Controller, cfg LimitEnforcerConfig) *LimitEnforcer {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 30 * time.Second
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 60 * time.Second
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 1 * time.Hour
	}
	if cfg.InactiveTimeout == 0 {
		cfg.InactiveTimeout = 24 * time.Hour
	}

	limitsCache := common.NewTrafficLimitsCache(cfg.NodeID, cfg.PanelAPIURL, cfg.APIKey)

	return &LimitEnforcer{
		controller:      controller,
		limitsCache:     limitsCache,
		checkInterval:   cfg.CheckInterval,
		stopChan:        make(chan struct{}),
		userTraffic:     make(map[int]*userTrafficEntry),
		cleanupInterval: cfg.CleanupInterval,
		inactiveTimeout: cfg.InactiveTimeout,
	}
}

// Start begins monitoring traffic and enforcing limits
func (le *LimitEnforcer) Start(ctx context.Context, refreshInterval time.Duration) {
	// Start limits cache auto-refresh
	le.limitsCache.StartAutoRefresh(refreshInterval)

	// Start traffic monitoring
	go le.monitorTraffic(ctx)

	// Start periodic cleanup of inactive users
	go le.periodicCleanup(ctx)

	log.Println("Limit enforcer started")
}

// Stop gracefully stops the limit enforcer
func (le *LimitEnforcer) Stop() {
	close(le.stopChan)
	le.limitsCache.Stop()
	log.Println("Limit enforcer stopped")
}

// GetLimitsCache returns the underlying traffic limits cache
func (le *LimitEnforcer) GetLimitsCache() *common.TrafficLimitsCache {
	return le.limitsCache
}

// GetMetrics returns current metrics snapshot
func (le *LimitEnforcer) GetMetrics() map[string]int64 {
	le.trafficMu.RLock()
	trackedUsers := int64(len(le.userTraffic))
	le.trafficMu.RUnlock()

	le.Metrics.TrackedUsers.Store(trackedUsers)
	le.Metrics.CachedLimits.Store(int64(le.limitsCache.Count()))

	return map[string]int64{
		"users_removed":          le.Metrics.UsersRemoved.Load(),
		"checks_performed":       le.Metrics.ChecksPerformed.Load(),
		"check_errors":           le.Metrics.CheckErrors.Load(),
		"refresh_count":          le.Metrics.RefreshCount.Load(),
		"tracked_users":          le.Metrics.TrackedUsers.Load(),
		"cached_limits":          le.Metrics.CachedLimits.Load(),
		"last_check_duration_ms": le.Metrics.LastCheckDuration.Load(),
		"last_check_time":        le.Metrics.LastCheckTime.Load(),
	}
}

// monitorTraffic periodically checks user traffic against limits
func (le *LimitEnforcer) monitorTraffic(ctx context.Context) {
	ticker := time.NewTicker(le.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-le.stopChan:
			return
		case <-ticker.C:
			le.checkAndEnforceLimits(ctx)
		}
	}
}

// periodicCleanup removes inactive users from tracking map
func (le *LimitEnforcer) periodicCleanup(ctx context.Context) {
	ticker := time.NewTicker(le.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-le.stopChan:
			return
		case <-ticker.C:
			le.cleanupInactiveUsers()
		}
	}
}

// cleanupInactiveUsers removes users not seen for inactiveTimeout duration
func (le *LimitEnforcer) cleanupInactiveUsers() {
	le.trafficMu.Lock()
	defer le.trafficMu.Unlock()

	now := time.Now()
	removed := 0

	for userID, entry := range le.userTraffic {
		if now.Sub(entry.lastSeen) > le.inactiveTimeout {
			delete(le.userTraffic, userID)
			removed++
		}
	}

	if removed > 0 {
		log.Printf("Limit enforcer cleanup: removed %d inactive users from tracking", removed)
	}
}

// checkAndEnforceLimits fetches user stats and removes users over their limits
func (le *LimitEnforcer) checkAndEnforceLimits(ctx context.Context) {
	startTime := time.Now()
	le.Metrics.ChecksPerformed.Add(1)
	le.Metrics.LastCheckTime.Store(startTime.Unix())

	defer func() {
		le.Metrics.LastCheckDuration.Store(time.Since(startTime).Milliseconds())
	}()

	b := le.controller.Backend()
	if b == nil {
		return
	}

	// Get user stats from xray (with reset=true to get delta)
	statsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	stats, err := b.GetStats(statsCtx, &common.StatRequest{
		Type:   common.StatType_UsersStat,
		Reset_: true, // Get delta since last check and reset counters
	})
	if err != nil {
		le.Metrics.CheckErrors.Add(1)
		log.Printf("Limit enforcer: failed to get user stats: %v", err)
		return
	}

	now := time.Now()

	// Track users to remove
	usersToRemove := make(map[string]int64) // email -> traffic

	le.trafficMu.Lock()
	for _, stat := range stats.GetStats() {
		// Parse user email from stat name (format: "user>>>email>>>traffic>>>uplink/downlink")
		userID, email := parseUserStatName(stat.GetName())
		if userID == 0 {
			continue
		}

		// Get or create traffic entry
		entry, exists := le.userTraffic[userID]
		if !exists {
			entry = &userTrafficEntry{}
			le.userTraffic[userID] = entry
		}

		// Accumulate traffic and update last seen
		entry.traffic += stat.GetValue()
		entry.lastSeen = now
		totalTraffic := entry.traffic

		// Check if user has a limit configured
		limit := le.limitsCache.GetLimit(userID)
		if limit <= 0 {
			continue // No limit configured, skip
		}

		// Check if over limit
		if totalTraffic >= limit {
			usersToRemove[email] = totalTraffic
			log.Printf("Limit enforcer: user %s (ID: %d) exceeded limit: %d >= %d bytes",
				email, userID, totalTraffic, limit)
		}
	}
	le.trafficMu.Unlock()

	// Remove users who exceeded their limits
	if len(usersToRemove) > 0 {
		le.removeOverLimitUsers(ctx, usersToRemove)
	}
}

// parseUserStatName parses user ID and email from xray stat name
// Format: "user>>>1.username>>>traffic>>>uplink" or "user>>>1.username>>>traffic>>>downlink"
func parseUserStatName(name string) (int, string) {
	parts := strings.Split(name, ">>>")
	if len(parts) < 2 || parts[0] != "user" {
		return 0, ""
	}

	email := parts[1]

	// Extract user ID from email (format: "id.username")
	emailParts := strings.SplitN(email, ".", 2)
	if len(emailParts) < 2 {
		return 0, email
	}

	userID, err := strconv.Atoi(emailParts[0])
	if err != nil {
		return 0, email
	}

	return userID, email
}

// removeOverLimitUsers removes users from all xray inbounds
func (le *LimitEnforcer) removeOverLimitUsers(ctx context.Context, users map[string]int64) {
	b := le.controller.Backend()
	if b == nil {
		return
	}

	// Create empty user entries to trigger removal
	for email, traffic := range users {
		// Create a user with empty inbounds to remove from all inbounds
		emptyUser := &common.User{
			Email:    email,
			Inbounds: []string{}, // Empty inbounds = remove from all
		}

		if err := b.SyncUser(ctx, emptyUser); err != nil {
			log.Printf("Limit enforcer: failed to remove user %s: %v", email, err)
		} else {
			le.Metrics.UsersRemoved.Add(1)
			log.Printf("Limit enforcer: removed user %s (exceeded limit by %d bytes)", email, traffic)
		}
	}
}

// ResetUserTraffic resets accumulated traffic for a user (called when limits are reset)
func (le *LimitEnforcer) ResetUserTraffic(userID int) {
	le.trafficMu.Lock()
	delete(le.userTraffic, userID)
	le.trafficMu.Unlock()
}

// ResetAllTraffic resets all accumulated traffic (called on full sync from panel)
func (le *LimitEnforcer) ResetAllTraffic() {
	le.trafficMu.Lock()
	le.userTraffic = make(map[int]*userTrafficEntry)
	le.trafficMu.Unlock()
}

// UpdateLimitsFromPush updates limits from a gRPC push
func (le *LimitEnforcer) UpdateLimitsFromPush(limits []common.NodeUserLimit, fullSync bool) {
	le.limitsCache.UpdateFromPush(limits, fullSync)

	if fullSync {
		// On full sync, reset traffic tracking
		le.ResetAllTraffic()
	}
}
