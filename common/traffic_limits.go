package common

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// NodeUserLimit represents a per-user per-node traffic limit
type NodeUserLimit struct {
	ID        int   `json:"id"`
	UserID    int   `json:"user_id"`
	NodeID    int   `json:"node_id"`
	DataLimit int64 `json:"data_limit"` // in bytes, 0 = unlimited
}

// NodeUserLimitsResponse from panel API
type NodeUserLimitsResponse struct {
	Limits []NodeUserLimit `json:"limits"`
	Total  int             `json:"total"`
}

// userLimitsData holds the limits map for atomic swap
type userLimitsData struct {
	limits map[int]int64
}

// TrafficLimitsCache caches per-user per-node limits with optimized performance
type TrafficLimitsCache struct {
	nodeID      int
	panelAPIURL string
	apiKey      string
	httpClient  *http.Client
	stopChan    chan struct{}
	logger      Logger

	// Atomic pointer for lock-free reads
	limitsPtr atomic.Pointer[userLimitsData]

	// Mutex only for refresh operations (writes)
	refreshMu sync.Mutex

	// ETag for conditional requests
	lastETag   string
	lastUpdate time.Time
	lastError  error

	// Exponential backoff state
	backoff struct {
		mu              sync.Mutex
		currentInterval time.Duration
		baseInterval    time.Duration
		maxInterval     time.Duration
		lastErrorTime   time.Time
	}
}

// Logger interface for flexible logging
type Logger interface {
	Printf(format string, v ...interface{})
	Errorf(format string, v ...interface{})
}

// defaultLogger uses fmt.Printf if no logger provided
type defaultLogger struct{}

func (d *defaultLogger) Printf(format string, v ...interface{}) {
	fmt.Printf(format, v...)
}

func (d *defaultLogger) Errorf(format string, v ...interface{}) {
	fmt.Printf("ERROR: "+format, v...)
}

// NewTrafficLimitsCache creates a new traffic limits cache with optimizations
func NewTrafficLimitsCache(nodeID int, panelAPIURL string, apiKey string) *TrafficLimitsCache {
	tlc := &TrafficLimitsCache{
		nodeID:      nodeID,
		panelAPIURL: panelAPIURL,
		apiKey:      apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  false, // Enable built-in compression
				DisableKeepAlives:   false,
				MaxIdleConnsPerHost: 5,
			},
		},
		stopChan: make(chan struct{}),
		logger:   &defaultLogger{},
	}

	// Initialize with empty limits
	tlc.limitsPtr.Store(&userLimitsData{limits: make(map[int]int64)})

	// Initialize backoff settings
	tlc.backoff.baseInterval = 1 * time.Second
	tlc.backoff.currentInterval = tlc.backoff.baseInterval
	tlc.backoff.maxInterval = 60 * time.Second

	return tlc
}

// SetLogger sets custom logger
func (tlc *TrafficLimitsCache) SetLogger(logger Logger) {
	tlc.logger = logger
}

// Refresh fetches latest limits from panel API
func (tlc *TrafficLimitsCache) Refresh() error {
	return tlc.RefreshWithContext(context.Background())
}

// RefreshWithContext fetches latest limits from panel API with context
// Supports ETag for conditional requests and gzip compression
func (tlc *TrafficLimitsCache) RefreshWithContext(ctx context.Context) error {
	tlc.refreshMu.Lock()
	defer tlc.refreshMu.Unlock()

	url := fmt.Sprintf("%s/api/node-user-limits/node/%d", tlc.panelAPIURL, tlc.nodeID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		tlc.recordError(fmt.Errorf("failed to create request: %w", err))
		return tlc.lastError
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tlc.apiKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip") // Request gzip compression

	// Send ETag for conditional request
	if tlc.lastETag != "" {
		req.Header.Set("If-None-Match", tlc.lastETag)
	}

	resp, err := tlc.httpClient.Do(req)
	if err != nil {
		tlc.recordError(fmt.Errorf("failed to fetch limits: %w", err))
		return tlc.lastError
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified - data hasn't changed
	if resp.StatusCode == http.StatusNotModified {
		tlc.lastUpdate = time.Now()
		tlc.lastError = nil
		tlc.resetBackoff()
		tlc.logger.Printf("Traffic limits unchanged (304), using cached data\n")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		tlc.recordError(fmt.Errorf("panel API returned status %d: %s", resp.StatusCode, string(body)))
		return tlc.lastError
	}

	// Handle gzip response
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			tlc.recordError(fmt.Errorf("failed to create gzip reader: %w", err))
			return tlc.lastError
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	var response NodeUserLimitsResponse
	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		tlc.recordError(fmt.Errorf("failed to decode response: %w", err))
		return tlc.lastError
	}

	// Build new limits map
	newLimits := make(map[int]int64, len(response.Limits))
	for _, limit := range response.Limits {
		newLimits[limit.UserID] = limit.DataLimit
	}

	// Atomic swap - lock-free for readers
	tlc.limitsPtr.Store(&userLimitsData{limits: newLimits})

	// Update metadata
	tlc.lastUpdate = time.Now()
	tlc.lastError = nil

	// Save ETag for next request
	if etag := resp.Header.Get("ETag"); etag != "" {
		tlc.lastETag = etag
	}

	// Reset backoff on success
	tlc.resetBackoff()

	return nil
}

// GetLimit returns the traffic limit for a user, returns 0 if no limit set
// This is now lock-free for maximum performance
func (tlc *TrafficLimitsCache) GetLimit(userID int) int64 {
	data := tlc.limitsPtr.Load()
	if data == nil || data.limits == nil {
		return 0
	}

	limit, exists := data.limits[userID]
	if !exists {
		return 0 // No limit configured
	}
	return limit
}

// HasLimit checks if a user has a limit configured
// This is now lock-free for maximum performance
func (tlc *TrafficLimitsCache) HasLimit(userID int) bool {
	data := tlc.limitsPtr.Load()
	if data == nil || data.limits == nil {
		return false
	}

	_, exists := data.limits[userID]
	return exists
}

// GetStats returns cache statistics
func (tlc *TrafficLimitsCache) GetStats() (total int, lastUpdate time.Time, lastError error) {
	tlc.refreshMu.Lock()
	defer tlc.refreshMu.Unlock()

	data := tlc.limitsPtr.Load()
	count := 0
	if data != nil && data.limits != nil {
		count = len(data.limits)
	}

	return count, tlc.lastUpdate, tlc.lastError
}

// Count returns the number of cached limits (lock-free)
func (tlc *TrafficLimitsCache) Count() int {
	data := tlc.limitsPtr.Load()
	if data == nil || data.limits == nil {
		return 0
	}
	return len(data.limits)
}

// UpdateFromPush updates the cache from a gRPC push (for future use)
// fullSync: true = replace all limits, false = incremental update
func (tlc *TrafficLimitsCache) UpdateFromPush(limits []NodeUserLimit, fullSync bool) {
	tlc.refreshMu.Lock()
	defer tlc.refreshMu.Unlock()

	var newLimits map[int]int64

	if fullSync {
		// Full replacement
		newLimits = make(map[int]int64, len(limits))
	} else {
		// Incremental: copy existing and update
		data := tlc.limitsPtr.Load()
		if data != nil && data.limits != nil {
			newLimits = make(map[int]int64, len(data.limits)+len(limits))
			for k, v := range data.limits {
				newLimits[k] = v
			}
		} else {
			newLimits = make(map[int]int64, len(limits))
		}
	}

	for _, limit := range limits {
		if limit.DataLimit == 0 && !fullSync {
			// Remove limit in incremental mode
			delete(newLimits, limit.UserID)
		} else {
			newLimits[limit.UserID] = limit.DataLimit
		}
	}

	tlc.limitsPtr.Store(&userLimitsData{limits: newLimits})
	tlc.lastUpdate = time.Now()
}

// recordError records an error and updates backoff state
func (tlc *TrafficLimitsCache) recordError(err error) {
	tlc.lastError = err

	tlc.backoff.mu.Lock()
	defer tlc.backoff.mu.Unlock()

	tlc.backoff.lastErrorTime = time.Now()

	// Exponential backoff: double the interval
	tlc.backoff.currentInterval = time.Duration(
		math.Min(
			float64(tlc.backoff.currentInterval*2),
			float64(tlc.backoff.maxInterval),
		),
	)
}

// resetBackoff resets the backoff interval to base
func (tlc *TrafficLimitsCache) resetBackoff() {
	tlc.backoff.mu.Lock()
	defer tlc.backoff.mu.Unlock()

	tlc.backoff.currentInterval = tlc.backoff.baseInterval
}

// getBackoffInterval returns the current backoff interval with jitter
func (tlc *TrafficLimitsCache) getBackoffInterval() time.Duration {
	tlc.backoff.mu.Lock()
	defer tlc.backoff.mu.Unlock()

	// Add jitter: ±20% to prevent thundering herd
	jitter := float64(tlc.backoff.currentInterval) * 0.2 * (rand.Float64()*2 - 1)
	return tlc.backoff.currentInterval + time.Duration(jitter)
}

// shouldUseBackoff checks if we should use backoff interval instead of normal interval
func (tlc *TrafficLimitsCache) shouldUseBackoff() bool {
	tlc.backoff.mu.Lock()
	defer tlc.backoff.mu.Unlock()

	// Use backoff if we had an error recently (within last 5 minutes)
	return time.Since(tlc.backoff.lastErrorTime) < 5*time.Minute &&
		tlc.backoff.currentInterval > tlc.backoff.baseInterval
}

// StartAutoRefresh starts automatic refresh of limits with graceful shutdown support
// Now includes exponential backoff on errors
func (tlc *TrafficLimitsCache) StartAutoRefresh(interval time.Duration) {
	go func() {
		// Initial refresh
		if err := tlc.Refresh(); err != nil {
			tlc.logger.Errorf("Failed initial traffic limits refresh: %v\n", err)
		} else {
			total, _, _ := tlc.GetStats()
			tlc.logger.Printf("Initial traffic limits loaded: %d limits\n", total)
		}

		for {
			// Determine next refresh interval
			var nextInterval time.Duration
			if tlc.shouldUseBackoff() {
				nextInterval = tlc.getBackoffInterval()
				tlc.logger.Printf("Using backoff interval: %v\n", nextInterval)
			} else {
				nextInterval = interval
			}

			timer := time.NewTimer(nextInterval)

			select {
			case <-timer.C:
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				if err := tlc.RefreshWithContext(ctx); err != nil {
					tlc.logger.Errorf("Failed to refresh traffic limits: %v\n", err)
				} else {
					total, lastUpdate, _ := tlc.GetStats()
					tlc.logger.Printf("Traffic limits refreshed: %d limits at %s\n", total, lastUpdate.Format(time.RFC3339))
				}
				cancel()
			case <-tlc.stopChan:
				timer.Stop()
				tlc.logger.Printf("Stopping traffic limits auto-refresh\n")
				return
			}
		}
	}()
}

// Stop gracefully stops the auto-refresh goroutine
func (tlc *TrafficLimitsCache) Stop() {
	close(tlc.stopChan)
}
