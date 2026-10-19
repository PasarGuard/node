package mtproto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
)

const testMarker = "pgm_0011223344556677"

// fakeStatsServer serves telemt's /metrics and GET /v1/users from fields a
// test sets, and counts the requests.
type fakeStatsServer struct {
	server *httptest.Server

	mu            sync.Mutex
	suppressed    int
	metrics       map[string]userMetrics
	metricsStatus int // 0 answers 200
	// onMetrics runs for each /metrics request before it is answered.
	onMetrics   func(f *fakeStatsServer)
	apiUsers    []telemtUserInfo
	usersStatus int // 0 answers 200
	calls       map[string]int
}

func newFakeStatsServer(t *testing.T) *fakeStatsServer {
	t.Helper()
	f := &fakeStatsServer{metrics: map[string]userMetrics{}, calls: map[string]int{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeStatsServer) set(apply func(f *fakeStatsServer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	apply(f)
}

func (f *fakeStatsServer) callCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

func (f *fakeStatsServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[r.URL.Path]++

	switch {
	case r.URL.Path == "/metrics":
		if f.onMetrics != nil {
			f.onMetrics(f)
		}
		if f.metricsStatus != 0 {
			http.Error(w, "metrics unavailable", f.metricsStatus)
			return
		}
		_, _ = fmt.Fprint(w, renderFakeMetrics(f.suppressed, f.metrics))
	case r.Method == http.MethodGet && r.URL.Path == "/v1/users":
		if f.usersStatus != 0 {
			writeFakeError(w, f.usersStatus, "internal_error", "failed to load config")
			return
		}
		writeFakeSuccess(w, http.StatusOK, f.apiUsers)
	default:
		writeFakeError(w, http.StatusNotFound, "not_found", "Route not found")
	}
}

// renderFakeMetrics writes users the way telemt 3.5.14 does.
func renderFakeMetrics(suppressed int, users map[string]userMetrics) string {
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(users)) {
		u := users[name]
		fmt.Fprintf(&b, "telemt_user_connections_total{user=%q} 1\n", name)
		fmt.Fprintf(&b, "telemt_user_connections_current{user=%q} %d\n", name, u.ConnectionsCurrent)
		fmt.Fprintf(&b, "telemt_user_octets_from_client_total{user=%q} %d\n", name, u.Uplink)
		fmt.Fprintf(&b, "telemt_user_octets_to_client_total{user=%q} %d\n", name, u.Downlink)
		fmt.Fprintf(&b, "telemt_user_unique_ips_current{user=%q} %d\n", name, u.UniqueIPsCurrent)
	}
	fmt.Fprintf(&b, "telemt_telemetry_user_series_suppressed %d\n", suppressed)
	return b.String()
}

// testClock is a clock tests move by hand; with step set, every reading
// also moves it on by step.
type testClock struct {
	mu   sync.Mutex
	now  time.Time
	step time.Duration
}

func newTestClock(step time.Duration) *testClock {
	return &testClock{now: time.Unix(1_800_000_000, 0), step: step}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(c.step)
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newStatsTestBackend returns a started backend reading stats from server.
// Its clock moves 2 s per reading, so every call refreshes, unless a test
// sets the step to zero.
func newStatsTestBackend(t *testing.T, server *fakeStatsServer, users ...string) (*MTProto, *testClock) {
	t.Helper()
	desired := make(map[string]*runtimeUser, len(users))
	for _, name := range users {
		desired[name] = &runtimeUser{Username: name, Secret: testSecret}
	}
	clock := newTestClock(2 * statsSnapshotMaxAge)
	m := &MTProto{
		config:         &Config{InboundTag: "mtproto"},
		process:        &processManager{run: &telemtRun{pid: 1, waitDone: make(chan struct{})}, generation: 1},
		apiClient:      newAPIClient(server.server.URL, "Bearer test"),
		metricsScraper: newMetricsScraper(server.server.URL + "/metrics"),
		tracker:        newTrafficTracker(),
		desired:        desired,
		statsClock:     clock.Now,
	}
	return m, clock
}

func getStats(t *testing.T, m *MTProto, statType common.StatType, reset bool) *common.StatResponse {
	t.Helper()
	response, err := m.GetStats(context.Background(), &common.StatRequest{Type: statType, Reset_: reset})
	if err != nil {
		t.Fatalf("GetStats(%v): %v", statType, err)
	}
	return response
}

func TestGetStats_MetricsUnavailable(t *testing.T) {
	m := metricsUnavailableBackend()

	stats, err := m.GetStats(context.Background(), &common.StatRequest{Type: common.StatType_UsersStat})
	if err != nil {
		t.Fatalf("GetStats should be best-effort, got %v", err)
	}
	if stats == nil || len(stats.GetStats()) != 0 {
		t.Errorf("expected empty stats, got %+v", stats)
	}

	online, err := m.GetUserOnlineStats(context.Background(), "alice")
	if err != nil {
		t.Fatalf("GetUserOnlineStats should be best-effort, got %v", err)
	}
	if online == nil || online.GetName() != "alice" || online.GetValue() != 0 {
		t.Errorf("expected zero online count, got %+v", online)
	}
}

func metricsUnavailableBackend() *MTProto {
	return &MTProto{
		config:         &Config{InboundTag: "mtproto"},
		process:        &processManager{run: &telemtRun{pid: 1, waitDone: make(chan struct{})}},
		metricsScraper: newMetricsScraper("http://127.0.0.1:1/metrics"),
		tracker:        newTrafficTracker(),
		desired:        map[string]*runtimeUser{"alice": {Username: "alice", Secret: testSecret}},
	}
}

// TestReaddedUserNotBilledTwice: telemt keeps a removed user's counters, so
// the tracker follows every user telemt reports, desired or not.
func TestReaddedUserNotBilledTwice(t *testing.T) {
	server := newFakeStatsServer(t)
	m, _ := newStatsTestBackend(t, server, "u1")

	server.set(func(f *fakeStatsServer) { f.metrics["u1"] = traffic(1000, 0) })
	assertTraffic(t, getStats(t, m, common.StatType_UsersStat, true), map[string]counters{"u1": {1000, 0}})

	m.stateMu.Lock()
	m.desired = map[string]*runtimeUser{}
	m.stateMu.Unlock()
	assertTraffic(t, getStats(t, m, common.StatType_UsersStat, true), map[string]counters{})

	m.stateMu.Lock()
	m.desired = map[string]*runtimeUser{"u1": {Username: "u1", Secret: testSecret}}
	m.stateMu.Unlock()
	server.set(func(f *fakeStatsServer) { f.metrics["u1"] = traffic(1200, 0) })
	assertTraffic(t, getStats(t, m, common.StatType_UsersStat, true), map[string]counters{"u1": {200, 0}})
}

// TestRemovedUserTrafficIsBilled: traffic telemt counts for a user after it
// left the desired set (its last interval, or a session still open) is
// reported.
func TestRemovedUserTrafficIsBilled(t *testing.T) {
	server := newFakeStatsServer(t)
	m, _ := newStatsTestBackend(t, server)

	server.set(func(f *fakeStatsServer) { f.metrics["u1"] = traffic(40, 60) })
	assertTraffic(t, getStats(t, m, common.StatType_UsersStat, true), map[string]counters{"u1": {40, 60}})
	assertTraffic(t, getStats(t, m, common.StatType_Outbounds, true), map[string]counters{"mtproto": {40, 60}})
}

func TestConcurrentRefreshDoesNotDoubleCount(t *testing.T) {
	server := newFakeStatsServer(t)
	m, _ := newStatsTestBackend(t, server, "u1")

	// Every scrape sees the counters grown by 10/20.
	server.set(func(f *fakeStatsServer) {
		f.onMetrics = func(f *fakeStatsServer) {
			u := f.metrics["u1"]
			f.metrics["u1"] = traffic(u.Uplink+10, u.Downlink+20)
		}
	})

	const workers, calls = 4, 25
	var mu sync.Mutex
	var reported counters
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range calls {
				response, err := m.GetStats(context.Background(), &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
				if err != nil {
					t.Errorf("GetStats: %v", err)
					return
				}
				got := trafficByName(t, response)["u1"]
				mu.Lock()
				reported.Up += got.Up
				reported.Down += got.Down
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	scrapes := server.callCount("/metrics")
	if scrapes != workers*calls {
		t.Errorf("%d scrapes, want %d (the clock makes every refresh stale)", scrapes, workers*calls)
	}
	var final userMetrics
	server.set(func(f *fakeStatsServer) { final = f.metrics["u1"] })
	if reported != (counters{final.Uplink, final.Downlink}) {
		t.Errorf("reported %v in total, want the final counters %d/%d", reported, final.Uplink, final.Downlink)
	}
}

func TestRefreshReusesRecentSnapshot(t *testing.T) {
	server := newFakeStatsServer(t)
	m, clock := newStatsTestBackend(t, server, "u1")
	clock.step = 0
	server.set(func(f *fakeStatsServer) { f.metrics["u1"] = traffic(5, 5) })

	getStats(t, m, common.StatType_UsersStat, false)
	getStats(t, m, common.StatType_Outbounds, false)
	if _, err := m.GetUserOnlineStats(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	clock.Advance(statsSnapshotMaxAge - time.Millisecond)
	getStats(t, m, common.StatType_UsersStat, false)
	if got := server.callCount("/metrics"); got != 1 {
		t.Errorf("%d scrapes within %s, want 1", got, statsSnapshotMaxAge)
	}

	clock.Advance(time.Millisecond)
	getStats(t, m, common.StatType_UsersStat, false)
	if got := server.callCount("/metrics"); got != 2 {
		t.Errorf("%d scrapes after %s, want 2", got, statsSnapshotMaxAge)
	}
}

// TestRestartDuringScrapeDiscardsSnapshot: a scrape that overlaps a telemt
// restart may hold either process's counters, so it is dropped.
func TestRestartDuringScrapeDiscardsSnapshot(t *testing.T) {
	server := newFakeStatsServer(t)
	m, _ := newStatsTestBackend(t, server, "u1")

	server.set(func(f *fakeStatsServer) {
		f.metrics["u1"] = traffic(70, 80)
		f.onMetrics = func(f *fakeStatsServer) {
			m.process.mu.Lock()
			m.process.generation++
			m.process.mu.Unlock()
			f.onMetrics = nil
		}
	})
	assertTraffic(t, getStats(t, m, common.StatType_UsersStat, true), map[string]counters{})
	assertTraffic(t, getStats(t, m, common.StatType_UsersStat, true), map[string]counters{"u1": {70, 80}})
}

func TestSuppressedSeriesSwitchToAPITotals(t *testing.T) {
	server := newFakeStatsServer(t)
	m, _ := newStatsTestBackend(t, server, "u1")
	var users, outbound counters
	poll := func(statType common.StatType, total *counters, want map[string]counters) {
		t.Helper()
		response := getStats(t, m, statType, true)
		assertTraffic(t, response, want)
		for _, got := range trafficByName(t, response) {
			total.Up += got.Up
			total.Down += got.Down
		}
	}

	server.set(func(f *fakeStatsServer) {
		f.metrics["u1"] = traffic(100, 200)
		f.metrics[testMarker] = traffic(9, 9)
	})
	poll(common.StatType_UsersStat, &users, map[string]counters{"u1": {100, 200}})
	server.set(func(f *fakeStatsServer) { f.metrics["u1"] = traffic(150, 250) })
	poll(common.StatType_Outbounds, &outbound, map[string]counters{"mtproto": {150, 250}})
	if got := server.callCount("/v1/users"); got != 0 {
		t.Errorf("%d user list calls while per-user metrics are complete, want 0", got)
	}

	// More users than telemt exports series for: u1's series are gone (or
	// stale), and its total comes from the user list.
	server.set(func(f *fakeStatsServer) {
		f.suppressed = 3
		f.metrics = map[string]userMetrics{"u9": traffic(1, 1)}
		f.apiUsers = []telemtUserInfo{
			{Username: "u1", TotalOctets: 400},
			{Username: testMarker, TotalOctets: 999},
		}
	})
	poll(common.StatType_UsersStat, &users, map[string]counters{"u1": {50, 50}})

	server.set(func(f *fakeStatsServer) { f.apiUsers[0].TotalOctets = 500 })
	poll(common.StatType_UsersStat, &users, map[string]counters{"u1": {0, 100}})
	poll(common.StatType_Outbounds, &outbound, map[string]counters{"mtproto": {0, 100}})
	usersCalls := server.callCount("/v1/users")
	if usersCalls != 3 {
		t.Errorf("%d user list calls in API-totals mode, want 3", usersCalls)
	}

	server.set(func(f *fakeStatsServer) {
		f.suppressed = 0
		f.metrics = map[string]userMetrics{"u1": traffic(200, 300)}
	})
	poll(common.StatType_UsersStat, &users, map[string]counters{})
	server.set(func(f *fakeStatsServer) { f.metrics["u1"] = traffic(210, 320) })
	poll(common.StatType_UsersStat, &users, map[string]counters{"u1": {10, 20}})
	poll(common.StatType_Outbounds, &outbound, map[string]counters{"mtproto": {10, 20}})
	if got := server.callCount("/v1/users"); got != usersCalls {
		t.Errorf("%d user list calls after per-user metrics came back, want %d", got, usersCalls)
	}

	// Every byte telemt counted (210+320) is billed once per family.
	if users.Up+users.Down != 530 || outbound.Up+outbound.Down != 530 {
		t.Errorf("billed users %v, outbound %v; want 530 bytes each", users, outbound)
	}
}

// TestFailedRefreshKeepsPendingTraffic: a user list that fails (telemt
// answers 5xx while a bad config is on disk) keeps the previous counters.
func TestFailedRefreshKeepsPendingTraffic(t *testing.T) {
	server := newFakeStatsServer(t)
	m, _ := newStatsTestBackend(t, server, "u1")

	server.set(func(f *fakeStatsServer) {
		f.suppressed = 1
		f.apiUsers = []telemtUserInfo{{Username: "u1", TotalOctets: 100}}
	})
	assertTraffic(t, getStats(t, m, common.StatType_UsersStat, true), map[string]counters{"u1": {0, 100}})

	server.set(func(f *fakeStatsServer) {
		f.usersStatus = http.StatusInternalServerError
		f.apiUsers[0].TotalOctets = 150
	})
	assertTraffic(t, getStats(t, m, common.StatType_UsersStat, true), map[string]counters{})

	server.set(func(f *fakeStatsServer) {
		f.usersStatus = 0
		f.apiUsers[0].TotalOctets = 170
	})
	assertTraffic(t, getStats(t, m, common.StatType_UsersStat, true), map[string]counters{"u1": {0, 70}})
}

func TestMarkerUsersNeverReported(t *testing.T) {
	server := newFakeStatsServer(t)
	m, _ := newStatsTestBackend(t, server, "u1")
	server.set(func(f *fakeStatsServer) {
		f.metrics["u1"] = userMetrics{Uplink: 1, Downlink: 2, UniqueIPsCurrent: 1}
		f.metrics[testMarker] = userMetrics{Uplink: 5, Downlink: 6, UniqueIPsCurrent: 1}
		f.metrics["pgm_ffeeddccbbaa9988"] = userMetrics{Uplink: 7, Downlink: 8, UniqueIPsCurrent: 1}
	})

	assertTraffic(t, getStats(t, m, common.StatType_UsersStat, false), map[string]counters{"u1": {1, 2}})
	assertTraffic(t, getStats(t, m, common.StatType_UserStat, false), map[string]counters{})
	response, err := m.GetStats(context.Background(), &common.StatRequest{Type: common.StatType_UserStat, Name: testMarker})
	if err != nil {
		t.Fatal(err)
	}
	assertTraffic(t, response, map[string]counters{})
	assertTraffic(t, getStats(t, m, common.StatType_Outbounds, false), map[string]counters{"mtproto": {1, 2}})
	assertTraffic(t, getStats(t, m, common.StatType_Inbounds, false), map[string]counters{"mtproto": {1, 2}})

	online, err := m.GetUserOnlineStats(context.Background(), testMarker)
	if err != nil || online.GetValue() != 0 {
		t.Errorf("marker online = %+v, %v; want 0", online, err)
	}
}

func TestOnlineStatIsUniqueIPs(t *testing.T) {
	server := newFakeStatsServer(t)
	m, _ := newStatsTestBackend(t, server, "u1")
	server.set(func(f *fakeStatsServer) {
		f.metrics["u1"] = userMetrics{ConnectionsCurrent: 5, UniqueIPsCurrent: 2}
	})

	online, err := m.GetUserOnlineStats(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if online.GetName() != "u1" || online.GetValue() != 2 {
		t.Errorf("online = %+v, want u1 with 2 unique IPs", online)
	}

	// With per-user series suppressed, the count comes from the user list.
	server.set(func(f *fakeStatsServer) {
		f.suppressed = 1
		f.apiUsers = []telemtUserInfo{{Username: "u1", CurrentConnections: 7, ActiveUniqueIPs: 3}}
	})
	online, err = m.GetUserOnlineStats(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if online.GetValue() != 3 {
		t.Errorf("online = %d with suppressed series, want 3", online.GetValue())
	}
}

// lockedBuffer is a bytes.Buffer safe for the log package and a test to
// share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog sends the standard logger's output to a buffer for one test.
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buffer := &lockedBuffer{}
	previous := log.Writer()
	log.SetOutput(buffer)
	t.Cleanup(func() { log.SetOutput(previous) })
	return buffer
}

func TestScrapeErrorIsLogged(t *testing.T) {
	logs := captureLog(t)
	server := newFakeStatsServer(t)
	m, clock := newStatsTestBackend(t, server, "u1")
	clock.step = 0
	server.set(func(f *fakeStatsServer) { f.metricsStatus = http.StatusInternalServerError })

	failures := func() int { return strings.Count(logs.String(), refreshFailedMessage) }
	for i := range 3 {
		if i > 0 {
			clock.Advance(2 * statsSnapshotMaxAge)
		}
		response := getStats(t, m, common.StatType_UsersStat, true)
		assertTraffic(t, response, map[string]counters{})
		if response.GetStats() == nil {
			t.Error("GetStats returned nil stats, want an empty list")
		}
	}
	if got := server.callCount("/metrics"); got != 3 {
		t.Errorf("%d scrapes, want 3", got)
	}
	if got := failures(); got != 1 {
		t.Errorf("logged %d failures in 4 s, want 1:\n%s", got, logs.String())
	}

	clock.Advance(refreshErrorLogInterval)
	getStats(t, m, common.StatType_UsersStat, true)
	if got := failures(); got != 2 {
		t.Errorf("logged %d failures after a minute, want 2:\n%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "500") {
		t.Errorf("the log does not carry the cause:\n%s", logs.String())
	}
}

func TestAPIUsersDecodeTotals(t *testing.T) {
	payload := `{"ok":true,"data":[{"username":"u1","total_octets":12345,"current_connections":4,"active_unique_ips":2}]}`
	var decoded apiSuccessResponse[[]telemtUserInfo]
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatal(err)
	}
	got := usersFromAPI(decoded.Data)
	if want := (userMetrics{Downlink: 12345, ConnectionsCurrent: 4, UniqueIPsCurrent: 2}); got["u1"] != want {
		t.Errorf("u1 = %+v, want %+v", got["u1"], want)
	}
}
