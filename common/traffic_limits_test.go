package common

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrafficLimitsCache_GetLimit_LockFree(t *testing.T) {
	tlc := NewTrafficLimitsCache(1, "http://localhost", "test-key")

	// Set some limits via push
	limits := []NodeUserLimit{
		{UserID: 1, DataLimit: 1000},
		{UserID: 2, DataLimit: 2000},
		{UserID: 3, DataLimit: 0}, // Unlimited
	}
	tlc.UpdateFromPush(limits, true)

	// Test GetLimit
	tests := []struct {
		userID   int
		expected int64
	}{
		{1, 1000},
		{2, 2000},
		{3, 0},
		{999, 0}, // Non-existent
	}

	for _, tt := range tests {
		got := tlc.GetLimit(tt.userID)
		if got != tt.expected {
			t.Errorf("GetLimit(%d) = %d, want %d", tt.userID, got, tt.expected)
		}
	}
}

func TestTrafficLimitsCache_HasLimit(t *testing.T) {
	tlc := NewTrafficLimitsCache(1, "http://localhost", "test-key")

	limits := []NodeUserLimit{
		{UserID: 1, DataLimit: 1000},
		{UserID: 2, DataLimit: 0}, // Explicit 0 is still a limit
	}
	tlc.UpdateFromPush(limits, true)

	tests := []struct {
		userID   int
		expected bool
	}{
		{1, true},
		{2, true},    // 0 is still a configured limit
		{999, false}, // Not configured
	}

	for _, tt := range tests {
		got := tlc.HasLimit(tt.userID)
		if got != tt.expected {
			t.Errorf("HasLimit(%d) = %v, want %v", tt.userID, got, tt.expected)
		}
	}
}

func TestTrafficLimitsCache_UpdateFromPush_FullSync(t *testing.T) {
	tlc := NewTrafficLimitsCache(1, "http://localhost", "test-key")

	// Initial limits
	tlc.UpdateFromPush([]NodeUserLimit{
		{UserID: 1, DataLimit: 1000},
		{UserID: 2, DataLimit: 2000},
	}, true)

	// Full sync - should replace all
	tlc.UpdateFromPush([]NodeUserLimit{
		{UserID: 3, DataLimit: 3000},
	}, true)

	if tlc.HasLimit(1) {
		t.Error("User 1 should not have limit after full sync")
	}
	if tlc.HasLimit(2) {
		t.Error("User 2 should not have limit after full sync")
	}
	if !tlc.HasLimit(3) {
		t.Error("User 3 should have limit after full sync")
	}
	if tlc.GetLimit(3) != 3000 {
		t.Errorf("User 3 limit = %d, want 3000", tlc.GetLimit(3))
	}
}

func TestTrafficLimitsCache_UpdateFromPush_Incremental(t *testing.T) {
	tlc := NewTrafficLimitsCache(1, "http://localhost", "test-key")

	// Initial limits
	tlc.UpdateFromPush([]NodeUserLimit{
		{UserID: 1, DataLimit: 1000},
		{UserID: 2, DataLimit: 2000},
	}, true)

	// Incremental update - should update user 1 and add user 3
	tlc.UpdateFromPush([]NodeUserLimit{
		{UserID: 1, DataLimit: 1500},
		{UserID: 3, DataLimit: 3000},
	}, false)

	if tlc.GetLimit(1) != 1500 {
		t.Errorf("User 1 limit = %d, want 1500", tlc.GetLimit(1))
	}
	if tlc.GetLimit(2) != 2000 {
		t.Errorf("User 2 limit = %d, want 2000 (unchanged)", tlc.GetLimit(2))
	}
	if tlc.GetLimit(3) != 3000 {
		t.Errorf("User 3 limit = %d, want 3000", tlc.GetLimit(3))
	}

	// Incremental update with 0 - should remove the limit
	tlc.UpdateFromPush([]NodeUserLimit{
		{UserID: 2, DataLimit: 0},
	}, false)

	if tlc.HasLimit(2) {
		t.Error("User 2 should not have limit after removal")
	}
}

func TestTrafficLimitsCache_ConcurrentAccess(t *testing.T) {
	tlc := NewTrafficLimitsCache(1, "http://localhost", "test-key")

	// Set initial limits
	tlc.UpdateFromPush([]NodeUserLimit{
		{UserID: 1, DataLimit: 1000},
	}, true)

	var wg sync.WaitGroup
	var reads int64 = 0
	numReaders := 100
	numWriters := 10
	iterations := 1000

	// Start readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = tlc.GetLimit(1)
				_ = tlc.HasLimit(1)
				atomic.AddInt64(&reads, 1)
			}
		}()
	}

	// Start writers
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations/10; j++ {
				tlc.UpdateFromPush([]NodeUserLimit{
					{UserID: 1, DataLimit: int64(j * id)},
				}, false)
			}
		}(i)
	}

	wg.Wait()
	t.Logf("Completed %d reads with concurrent writes", atomic.LoadInt64(&reads))
}

func TestTrafficLimitsCache_ETagHandling(t *testing.T) {
	// Create a test server that supports ETag
	etag := `"test-etag-12345"`
	limits := NodeUserLimitsResponse{
		Limits: []NodeUserLimit{
			{ID: 1, UserID: 100, NodeID: 1, DataLimit: 5000},
		},
		Total: 1,
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// Check If-None-Match header
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		// Set ETag and return data
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(limits)
	}))
	defer server.Close()

	tlc := NewTrafficLimitsCache(1, server.URL, "test-key")

	// First request - should get data
	err := tlc.Refresh()
	if err != nil {
		t.Fatalf("First refresh failed: %v", err)
	}
	if tlc.GetLimit(100) != 5000 {
		t.Errorf("After first refresh: limit = %d, want 5000", tlc.GetLimit(100))
	}
	if requestCount != 1 {
		t.Errorf("Request count = %d, want 1", requestCount)
	}

	// Second request - should get 304
	err = tlc.Refresh()
	if err != nil {
		t.Fatalf("Second refresh failed: %v", err)
	}
	if tlc.GetLimit(100) != 5000 {
		t.Errorf("After second refresh: limit = %d, want 5000 (unchanged)", tlc.GetLimit(100))
	}
	if requestCount != 2 {
		t.Errorf("Request count = %d, want 2", requestCount)
	}
}

func TestTrafficLimitsCache_ExponentialBackoff(t *testing.T) {
	// Create a failing server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	tlc := NewTrafficLimitsCache(1, server.URL, "test-key")

	// First error - should start backoff
	_ = tlc.Refresh()
	if !tlc.shouldUseBackoff() {
		t.Error("Should use backoff after first error")
	}

	initial := tlc.backoff.currentInterval

	// Second error - should double
	_ = tlc.Refresh()
	if tlc.backoff.currentInterval <= initial {
		t.Error("Backoff interval should increase after second error")
	}

	// Successful request resets backoff
	successServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(NodeUserLimitsResponse{Limits: []NodeUserLimit{}, Total: 0})
	}))
	defer successServer.Close()

	tlc.panelAPIURL = successServer.URL
	_ = tlc.Refresh()

	if tlc.backoff.currentInterval != tlc.backoff.baseInterval {
		t.Error("Backoff should reset after successful request")
	}
}

func TestTrafficLimitsCache_GetStats(t *testing.T) {
	tlc := NewTrafficLimitsCache(1, "http://localhost", "test-key")

	// Initially empty
	total, lastUpdate, lastError := tlc.GetStats()
	if total != 0 {
		t.Errorf("Initial total = %d, want 0", total)
	}
	if !lastUpdate.IsZero() {
		t.Error("Initial lastUpdate should be zero")
	}
	if lastError != nil {
		t.Error("Initial lastError should be nil")
	}

	// Add some limits
	tlc.UpdateFromPush([]NodeUserLimit{
		{UserID: 1, DataLimit: 1000},
		{UserID: 2, DataLimit: 2000},
	}, true)

	total, lastUpdate, lastError = tlc.GetStats()
	if total != 2 {
		t.Errorf("After push: total = %d, want 2", total)
	}
	if lastUpdate.IsZero() {
		t.Error("After push: lastUpdate should not be zero")
	}
}

func TestTrafficLimitsCache_Stop(t *testing.T) {
	tlc := NewTrafficLimitsCache(1, "http://localhost", "test-key")

	// Start auto-refresh
	tlc.StartAutoRefresh(100 * time.Millisecond)

	// Give it time to do at least one refresh
	time.Sleep(50 * time.Millisecond)

	// Stop should not panic
	tlc.Stop()

	// Give it time to stop
	time.Sleep(50 * time.Millisecond)
}

func TestTrafficLimitsCache_RefreshWithContext_Cancellation(t *testing.T) {
	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tlc := NewTrafficLimitsCache(1, server.URL, "test-key")

	// Create a context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := tlc.RefreshWithContext(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Error("Expected error due to context cancellation")
	}
	if elapsed > 1*time.Second {
		t.Errorf("Request should have been cancelled quickly, took %v", elapsed)
	}
}
