package mtproto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
)

const otherSecret = "ffeeddccbbaa00112233445566778899"

var markerUsernamePattern = regexp.MustCompile(`^pgm_[0-9a-f]{16}$`)

// fakeTelemtAPI stands in for telemt's control API. It keeps the users of
// the config file (disk) and of the running config (runtime), records every
// call, and plays telemt's config watcher: a changed config file reaches the
// running config when GET /v1/users is polled, after reloadDelayPolls polls,
// unless rejectReload is set.
type fakeTelemtAPI struct {
	t          *testing.T
	server     *httptest.Server
	configPath string

	mu      sync.Mutex
	disk    map[string]string // username to secret
	runtime map[string]string
	calls   []string // "METHOD /path" per request

	rejectReload     bool
	reloadDelayPolls int
	appliedConfig    string // the config file content runtime was loaded from
	pendingConfig    string // a changed config file waiting to be applied
	pendingPolls     int
	// rejectedConfig is the last changed config file rejectReload kept out.
	rejectedConfig string

	failPatch bool // PATCH answers 500
	activeIPs map[string][]string
}

func newFakeTelemtAPI(t *testing.T) *fakeTelemtAPI {
	t.Helper()
	f := &fakeTelemtAPI{
		t:          t,
		configPath: filepath.Join(t.TempDir(), "config.toml"),
		disk:       make(map[string]string),
		runtime:    make(map[string]string),
		activeIPs:  make(map[string][]string),
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

// takeCalls returns the calls recorded so far and forgets them.
func (f *fakeTelemtAPI) takeCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	calls := f.calls
	f.calls = nil
	return calls
}

// realRuntimeUsers returns the running users without marker users.
func (f *fakeTelemtAPI) realRuntimeUsers() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	users := make(map[string]string)
	for name, secret := range f.runtime {
		if !strings.HasPrefix(name, markerUsernamePrefix) {
			users[name] = secret
		}
	}
	return users
}

// runtimeMarkers lists the marker users in the running config.
func (f *fakeTelemtAPI) runtimeMarkers() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var markers []string
	for name := range f.runtime {
		if strings.HasPrefix(name, markerUsernamePrefix) {
			markers = append(markers, name)
		}
	}
	return markers
}

func (f *fakeTelemtAPI) set(apply func(f *fakeTelemtAPI)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	apply(f)
}

// startLocked loads the config file into disk and runtime, as a telemt start.
func (f *fakeTelemtAPI) startLocked() {
	data, err := os.ReadFile(f.configPath)
	if err != nil {
		f.t.Errorf("fake telemt: reading the config: %v", err)
		return
	}
	f.disk = parseConfigUsers(string(data))
	f.runtime = maps.Clone(f.disk)
	f.appliedConfig = string(data)
}

// watchConfigLocked plays telemt's config watcher.
func (f *fakeTelemtAPI) watchConfigLocked() {
	data, err := os.ReadFile(f.configPath)
	if err != nil {
		return // no config file: the test set the users directly
	}
	content := string(data)
	f.disk = parseConfigUsers(content)
	if content == f.appliedConfig {
		return
	}
	if f.rejectReload {
		f.rejectedConfig = content
		return
	}
	if content != f.pendingConfig {
		f.pendingConfig = content
		f.pendingPolls = f.reloadDelayPolls
	}
	if f.pendingPolls > 0 {
		f.pendingPolls--
		return
	}
	f.runtime = maps.Clone(f.disk)
	f.appliedConfig = content
}

// parseConfigUsers reads [access.users] from a rendered config.
func parseConfigUsers(config string) map[string]string {
	users := make(map[string]string)
	section := ""
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section != "access.users" {
			continue
		}
		secret, err := strconv.Unquote(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		users[strings.Trim(strings.TrimSpace(key), `"`)] = secret
	}
	return users
}

// configMarkers lists the marker users of a rendered config.
func configMarkers(config string) []string {
	var markers []string
	for name := range parseConfigUsers(config) {
		if strings.HasPrefix(name, markerUsernamePrefix) {
			markers = append(markers, name)
		}
	}
	return markers
}

func (f *fakeTelemtAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	body, _ := io.ReadAll(r.Body)
	path := r.URL.Path
	f.calls = append(f.calls, r.Method+" "+path)

	switch {
	case r.Method == http.MethodGet && path == "/v1/stats/users/active-ips":
		type entry struct {
			Username  string   `json:"username"`
			ActiveIPs []string `json:"active_ips"`
		}
		data := []entry{}
		for name, ips := range f.activeIPs {
			data = append(data, entry{Username: name, ActiveIPs: ips})
		}
		writeFakeSuccess(w, http.StatusOK, data)

	case r.Method == http.MethodGet && path == "/v1/users":
		// telemt lists the users of the config file and computes in_runtime
		// from the running config.
		f.watchConfigLocked()
		data := []map[string]any{}
		for name := range f.disk {
			_, inRuntime := f.runtime[name]
			data = append(data, map[string]any{"username": name, "in_runtime": inRuntime})
		}
		writeFakeSuccess(w, http.StatusOK, data)

	case r.Method == http.MethodPost && path == "/v1/users":
		var request telemtCreateUserRequest
		if err := json.Unmarshal(body, &request); err != nil {
			writeFakeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		if _, exists := f.runtime[request.Username]; exists {
			writeFakeError(w, http.StatusConflict, "user_exists", "User already exists")
			return
		}
		f.runtime[request.Username] = request.Secret
		f.disk[request.Username] = request.Secret
		writeFakeSuccess(w, http.StatusCreated, map[string]any{"user": map[string]any{"username": request.Username}})

	case strings.HasPrefix(path, "/v1/users/"):
		name := strings.TrimPrefix(path, "/v1/users/")
		if _, exists := f.runtime[name]; !exists {
			writeFakeError(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		switch r.Method {
		case http.MethodPatch:
			if f.failPatch {
				writeFakeError(w, http.StatusInternalServerError, "internal_error", "patch failed")
				return
			}
			var request telemtPatchUserRequest
			if err := json.Unmarshal(body, &request); err != nil {
				writeFakeError(w, http.StatusBadRequest, "bad_request", err.Error())
				return
			}
			if request.Secret != "" {
				f.runtime[name] = request.Secret
				f.disk[name] = request.Secret
			}
			writeFakeSuccess(w, http.StatusOK, map[string]any{"username": name})
		case http.MethodDelete:
			if len(f.runtime) == 1 {
				writeFakeError(w, http.StatusConflict, "last_user_forbidden", "Cannot delete the last user")
				return
			}
			delete(f.runtime, name)
			delete(f.disk, name)
			writeFakeSuccess(w, http.StatusOK, name)
		default:
			// A GET of one user loads the whole config in telemt; the node
			// must not need it.
			writeFakeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "unexpected "+r.Method)
		}

	default:
		writeFakeError(w, http.StatusNotFound, "not_found", "Route not found")
	}
}

func writeFakeSuccess(w http.ResponseWriter, status int, data any) {
	payload, _ := json.Marshal(map[string]any{"ok": true, "data": data, "revision": "r"})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func writeFakeError(w http.ResponseWriter, status int, code, message string) {
	payload, _ := json.Marshal(map[string]any{
		"ok":         false,
		"error":      map[string]string{"code": code, "message": message},
		"request_id": 1,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

// newSyncTestBackend returns a backend whose telemt "runs" on api: the
// process is a stand-in that counts as started (signalling it does nothing,
// like telemt on Windows, where its config watcher picks the file up), and
// the fake is started on the initial render.
func newSyncTestBackend(t *testing.T, api *fakeTelemtAPI, users []*common.User) *MTProto {
	t.Helper()

	mtConfig, err := NewConfig(`{"inbound_tag": "mtproto", "server": {"port": 8443}}`)
	if err != nil {
		t.Fatal(err)
	}
	desired, _ := ActiveUsersFromCommon(users, mtConfig.InboundTag)

	lifetime, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m := &MTProto{
		config: mtConfig,
		process: &processManager{
			run:         &telemtRun{pid: 1, waitDone: make(chan struct{})},
			startupTail: newLineRing(telemtStartupTailSize),
		},
		configPath:     api.configPath,
		apiClient:      newAPIClient(api.server.URL, "Bearer test"),
		metricsScraper: newMetricsScraper("http://127.0.0.1:1/metrics"),
		tracker:        newTrafficTracker(),
		apiPort:        20001,
		metricsPort:    20002,
		apiAuthHeader:  "Bearer test",
		desired:        cloneRuntimeUserMap(desired),
		lifetime:       lifetime,
		cancel:         cancel,
	}
	if err := m.writeRenderedConfigLocked(m.desired); err != nil {
		t.Fatal(err)
	}
	api.set(func(f *fakeTelemtAPI) { f.startLocked() })
	return m
}

// lowerMarkerConfirmTimeout sets markerConfirmTimeout for one test.
func lowerMarkerConfirmTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	previous := markerConfirmTimeout
	markerConfirmTimeout = timeout
	t.Cleanup(func() { markerConfirmTimeout = previous })
}

func desiredNames(m *MTProto) []string {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	names := make([]string, 0, len(m.desired))
	for name := range m.desired {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func desiredSecret(m *MTProto, name string) string {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	if user := m.desired[name]; user != nil {
		return user.Secret
	}
	return ""
}

func readConfig(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertCalls(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("telemt API calls = %q, want %q", got, want)
	}
}

func untagged(email string) *common.User {
	return &common.User{Email: email, Proxies: &common.Proxy{Mtproto: &common.Mtproto{Secret: testSecret}}}
}

func numberedSecret(i int) string {
	return fmt.Sprintf("%032x", i+1)
}

func TestPartialSkipsUnchangedUsers(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{
		mtUser("u1", "mtproto", testSecret),
		mtUser("u2", "mtproto", testSecret),
	})

	err := m.UpdateUsers(context.Background(), []*common.User{
		mtUser("u1", "mtproto", testSecret),
		mtUser("u2", "mtproto", otherSecret),
	})
	if err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	assertCalls(t, api.takeCalls(), "PATCH /v1/users/u2")
	if got := desiredSecret(m, "u2"); got != otherSecret {
		t.Errorf("desired u2 secret = %q, want %q", got, otherSecret)
	}
	if got := api.realRuntimeUsers()["u2"]; got != otherSecret {
		t.Errorf("telemt u2 secret = %q, want %q", got, otherSecret)
	}

	// A batch with nothing new reaches telemt not at all.
	if err := m.UpdateUsers(context.Background(), []*common.User{mtUser("u1", "mtproto", testSecret)}); err != nil {
		t.Fatalf("UpdateUsers (unchanged): %v", err)
	}
	assertCalls(t, api.takeCalls())
}

func TestPartialCreatesAndDeletesWithoutGet(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{
		mtUser("u1", "mtproto", testSecret),
		mtUser("u2", "mtproto", testSecret),
	})
	ctx := context.Background()

	if err := m.UpdateUsers(ctx, []*common.User{mtUser("u3", "mtproto", testSecret), untagged("u1")}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	assertCalls(t, api.takeCalls(), "POST /v1/users", "DELETE /v1/users/u1")
	if got := desiredNames(m); !slices.Equal(got, []string{"u2", "u3"}) {
		t.Errorf("desired = %q, want u2, u3", got)
	}

	t.Run("patch of a user telemt lacks creates it", func(t *testing.T) {
		api.set(func(f *fakeTelemtAPI) { delete(f.runtime, "u2") })
		if err := m.SyncUser(ctx, mtUser("u2", "mtproto", otherSecret)); err != nil {
			t.Fatalf("SyncUser: %v", err)
		}
		assertCalls(t, api.takeCalls(), "PATCH /v1/users/u2", "POST /v1/users")
		if got := api.realRuntimeUsers()["u2"]; got != otherSecret {
			t.Errorf("telemt u2 secret = %q, want %q", got, otherSecret)
		}
	})

	t.Run("create of a user telemt has patches it", func(t *testing.T) {
		api.set(func(f *fakeTelemtAPI) { f.runtime["u4"] = testSecret })
		if err := m.SyncUser(ctx, mtUser("u4", "mtproto", otherSecret)); err != nil {
			t.Fatalf("SyncUser: %v", err)
		}
		assertCalls(t, api.takeCalls(), "POST /v1/users", "PATCH /v1/users/u4")
		if got := api.realRuntimeUsers()["u4"]; got != otherSecret {
			t.Errorf("telemt u4 secret = %q, want %q", got, otherSecret)
		}
	})

	t.Run("delete of a user telemt lacks succeeds", func(t *testing.T) {
		api.set(func(f *fakeTelemtAPI) { delete(f.runtime, "u3") })
		if err := m.SyncUser(ctx, untagged("u3")); err != nil {
			t.Fatalf("SyncUser: %v", err)
		}
		assertCalls(t, api.takeCalls(), "DELETE /v1/users/u3")
		if got := desiredNames(m); !slices.Equal(got, []string{"u2", "u4"}) {
			t.Errorf("desired = %q, want u2, u4", got)
		}
	})
}

func TestLargeBatchUsesFullRenderAndReload(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u0", "mtproto", testSecret)})
	before, err := os.Stat(api.configPath)
	if err != nil {
		t.Fatal(err)
	}

	users := make([]*common.User, 0, partialApplyMaxUsers+1)
	for i := 1; i <= partialApplyMaxUsers+1; i++ {
		users = append(users, mtUser(fmt.Sprintf("u%d", i), "mtproto", numberedSecret(i)))
	}
	if err := m.UpdateUsers(context.Background(), users); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}

	// No per-user call: one render, then one poll that finds the marker.
	assertCalls(t, api.takeCalls(), "GET /v1/users")
	after, err := os.Stat(api.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Error("the config was not rendered again before the reload")
	}
	runtime := api.realRuntimeUsers()
	if len(runtime) != partialApplyMaxUsers+2 || runtime["u33"] != numberedSecret(33) || runtime["u0"] != testSecret {
		t.Errorf("telemt users after the reload = %v, want u0 to u33", runtime)
	}
	if got := len(desiredNames(m)); got != partialApplyMaxUsers+2 {
		t.Errorf("desired has %d users, want %d", got, partialApplyMaxUsers+2)
	}
}

// TestMarkerUserPerRender: every render carries exactly one disabled marker
// user with a fresh name, the backend reports the current one, and the
// marker never becomes a desired user.
func TestMarkerUserPerRender(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})

	seen := map[string]bool{}
	for _, users := range [][]*common.User{
		{mtUser("u2", "mtproto", testSecret)},
		{mtUser("u3", "mtproto", testSecret)},
	} {
		if err := m.SyncUsers(context.Background(), users); err != nil {
			t.Fatalf("SyncUsers: %v", err)
		}
		config := readConfig(t, api.configPath)
		markers := configMarkers(config)
		if len(markers) != 1 || !markerUsernamePattern.MatchString(markers[0]) {
			t.Fatalf("config markers = %q, want one pgm_<16 hex>", markers)
		}
		marker := markers[0]
		if seen[marker] {
			t.Errorf("marker %s was reused", marker)
		}
		seen[marker] = true
		if got := m.markerUsername(); got != marker {
			t.Errorf("markerUsername() = %q, want %q", got, marker)
		}
		if !strings.Contains(config, "[access.user_enabled]\n"+marker+" = false") {
			t.Errorf("marker %s is not rendered disabled:\n%s", marker, config)
		}
		if slices.Contains(desiredNames(m), marker) {
			t.Errorf("marker %s is in desired", marker)
		}
		if got := api.runtimeMarkers(); !slices.Equal(got, []string{marker}) {
			t.Errorf("telemt markers = %q, want %q", got, marker)
		}
	}
}

// TestHotReloadWaitsForMarker: telemt applies a config some polls after the
// write (its watcher or an earlier reload is still busy); the sync waits for
// the marker instead of failing.
func TestHotReloadWaitsForMarker(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})
	api.set(func(f *fakeTelemtAPI) { f.reloadDelayPolls = 3 })

	if err := m.SyncUsers(context.Background(), []*common.User{mtUser("u2", "mtproto", testSecret)}); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}
	assertCalls(t, api.takeCalls(), "GET /v1/users", "GET /v1/users", "GET /v1/users", "GET /v1/users")
	if got := desiredNames(m); !slices.Equal(got, []string{"u2"}) {
		t.Errorf("desired = %q, want u2", got)
	}
	if runtime := api.realRuntimeUsers(); len(runtime) != 1 || runtime["u2"] == "" {
		t.Errorf("telemt users = %v, want u2", runtime)
	}
}

// TestRejectedHotReloadRestoresPreviousUsers: telemt never loads the new
// config (it rejected it), so the marker never reaches its running config.
// The sync fails with telemt's last output, desired is unchanged, and the
// previous users are rendered again with a new marker.
func TestRejectedHotReloadRestoresPreviousUsers(t *testing.T) {
	lowerMarkerConfirmTimeout(t, 600*time.Millisecond)
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})
	m.process.startupTail.add("config reload rejected: bad listener")
	api.set(func(f *fakeTelemtAPI) { f.rejectReload = true })

	err := m.SyncUsers(context.Background(), []*common.User{mtUser("u2", "mtproto", otherSecret)})
	if err == nil || !strings.Contains(err.Error(), "bad listener") {
		t.Fatalf("SyncUsers = %v, want an error with telemt's last output", err)
	}
	if got := desiredNames(m); !slices.Equal(got, []string{"u1"}) {
		t.Errorf("desired = %q after a rejected reload, want u1", got)
	}
	if !m.process.Started() {
		t.Error("a rejected reload stopped telemt")
	}

	config := readConfig(t, api.configPath)
	users := parseConfigUsers(config)
	if users["u1"] != testSecret || users["u2"] != "" {
		t.Errorf("config after a rejected reload is not the previous user set:\n%s", config)
	}
	var rejected string
	api.set(func(f *fakeTelemtAPI) { rejected = f.rejectedConfig })
	rejectedMarkers, restoredMarkers := configMarkers(rejected), configMarkers(config)
	if len(rejectedMarkers) != 1 || len(restoredMarkers) != 1 || rejectedMarkers[0] == restoredMarkers[0] {
		t.Errorf("markers: rejected %q, restored %q; want one each and a new one for the restore", rejectedMarkers, restoredMarkers)
	}
}

func TestFullSyncWithoutChangesSkipsReload(t *testing.T) {
	api := newFakeTelemtAPI(t)
	users := []*common.User{mtUser("u1", "mtproto", testSecret), mtUser("u2", "mtproto", testSecret)}
	m := newSyncTestBackend(t, api, users)

	if err := m.SyncUsers(context.Background(), users); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}
	assertCalls(t, api.takeCalls())

	m.syncMu.Lock()
	m.needsFullApply = true
	m.syncMu.Unlock()
	if err := m.SyncUsers(context.Background(), users); err != nil {
		t.Fatalf("SyncUsers (unconfirmed): %v", err)
	}
	assertCalls(t, api.takeCalls(), "GET /v1/users")
}

// TestLastRealUserGoesThroughAPI: the marker keeps telemt's user list
// non-empty, so the last real user is deleted, and the first one created,
// through the user API.
func TestLastRealUserGoesThroughAPI(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})
	ctx := context.Background()

	if err := m.UpdateUsers(ctx, []*common.User{untagged("u1")}); err != nil {
		t.Fatalf("UpdateUsers to zero users: %v", err)
	}
	assertCalls(t, api.takeCalls(), "DELETE /v1/users/u1")
	if got := desiredNames(m); len(got) != 0 {
		t.Errorf("desired = %q, want none", got)
	}
	if runtime := api.realRuntimeUsers(); len(runtime) != 0 {
		t.Errorf("telemt users = %v, want only the marker", runtime)
	}

	if err := m.SyncUser(ctx, mtUser("u2", "mtproto", testSecret)); err != nil {
		t.Fatalf("SyncUser from zero users: %v", err)
	}
	assertCalls(t, api.takeCalls(), "POST /v1/users")
	if runtime := api.realRuntimeUsers(); len(runtime) != 1 || runtime["u2"] == "" {
		t.Errorf("telemt users = %v, want u2", runtime)
	}

	// A full sync to zero users renders the marker alone.
	if err := m.SyncUsers(ctx, nil); err != nil {
		t.Fatalf("SyncUsers to zero users: %v", err)
	}
	assertCalls(t, api.takeCalls(), "GET /v1/users")
	if runtime := api.realRuntimeUsers(); len(runtime) != 0 {
		t.Errorf("telemt users = %v, want only the marker", runtime)
	}
	if markers := api.runtimeMarkers(); len(markers) != 1 {
		t.Errorf("telemt markers = %q, want one", markers)
	}
}

func TestInvalidUserDoesNotFailBatch(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})

	broken := &common.User{Email: "u2", Inbounds: []string{"mtproto"}}
	if err := m.SyncUsers(context.Background(), []*common.User{mtUser("u3", "mtproto", testSecret), broken}); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}
	if got := desiredNames(m); !slices.Equal(got, []string{"u3"}) {
		t.Errorf("desired = %q, want u3", got)
	}

	if err := m.UpdateUsers(context.Background(), []*common.User{mtUser("u4", "mtproto", testSecret), broken}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	if got := desiredNames(m); !slices.Equal(got, []string{"u3", "u4"}) {
		t.Errorf("desired = %q, want u3, u4", got)
	}
}

func TestOnlineIPListUsesBulkEndpoint(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{
		mtUser("u1", "mtproto", testSecret),
		mtUser("u2", "mtproto", testSecret),
	})
	api.set(func(f *fakeTelemtAPI) {
		f.activeIPs = map[string][]string{"u1": {"203.0.113.7", "2001:db8::1"}, "u2": {"198.51.100.1"}}
	})

	response, err := m.GetUserOnlineIpListStats(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GetUserOnlineIpListStats: %v", err)
	}
	assertCalls(t, api.takeCalls(), "GET /v1/stats/users/active-ips")
	if len(response.GetIps()) != 2 || response.GetIps()["203.0.113.7"] == 0 || response.GetIps()["2001:db8::1"] == 0 {
		t.Errorf("Ips = %v, want the two addresses of u1", response.GetIps())
	}
}

// TestUnconfirmedReloadForcesFullApply: the caller gives up before telemt
// loaded the config. telemt keeps running, desired keeps the confirmed
// users, and the next sync renders and reloads everything instead of a diff.
func TestUnconfirmedReloadForcesFullApply(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{
		mtUser("u1", "mtproto", testSecret),
		mtUser("u2", "mtproto", testSecret),
	})
	api.set(func(f *fakeTelemtAPI) { f.rejectReload = true })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := m.SyncUsers(ctx, []*common.User{mtUser("u1", "mtproto", testSecret), mtUser("u3", "mtproto", testSecret)})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SyncUsers = %v, want a deadline error", err)
	}
	if got := desiredNames(m); !slices.Equal(got, []string{"u1", "u2"}) {
		t.Errorf("desired = %q after an unconfirmed reload, want u1, u2", got)
	}
	if !m.process.Started() {
		t.Error("an unconfirmed reload stopped telemt")
	}
	api.takeCalls()

	api.set(func(f *fakeTelemtAPI) { f.rejectReload = false })
	if err := m.UpdateUsers(context.Background(), []*common.User{mtUser("u2", "mtproto", otherSecret)}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	assertCalls(t, api.takeCalls(), "GET /v1/users")
	if got := desiredNames(m); !slices.Equal(got, []string{"u1", "u2"}) {
		t.Errorf("desired = %q, want u1, u2", got)
	}
	if runtime := api.realRuntimeUsers(); len(runtime) != 2 || runtime["u2"] != otherSecret {
		t.Errorf("telemt users = %v, want u1 and the new u2", runtime)
	}

	// Confirmed again: the next small change is a diff.
	if err := m.UpdateUsers(context.Background(), []*common.User{mtUser("u1", "mtproto", otherSecret)}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	assertCalls(t, api.takeCalls(), "PATCH /v1/users/u1")
}

func TestPartialFailureFallsBackToFullApply(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{
		mtUser("u1", "mtproto", testSecret),
		mtUser("u2", "mtproto", testSecret),
	})
	api.set(func(f *fakeTelemtAPI) { f.failPatch = true })

	if err := m.UpdateUsers(context.Background(), []*common.User{mtUser("u2", "mtproto", otherSecret)}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	assertCalls(t, api.takeCalls(), "PATCH /v1/users/u2", "GET /v1/users")
	if got := api.realRuntimeUsers()["u2"]; got != otherSecret {
		t.Errorf("telemt u2 secret = %q, want %q", got, otherSecret)
	}
	if got := desiredSecret(m, "u2"); got != otherSecret {
		t.Errorf("desired u2 secret = %q, want %q", got, otherSecret)
	}
}

func TestRuntimeUserEqual(t *testing.T) {
	base := runtimeUser{Username: "u1", Secret: testSecret, UserAdTag: otherSecret, MaxTCPConns: 2, MaxUniqueIPs: 3}
	same := base
	if !runtimeUserEqual(&base, &same) {
		t.Error("identical users compare unequal")
	}
	for name, change := range map[string]func(u *runtimeUser){
		"secret":         func(u *runtimeUser) { u.Secret = otherSecret },
		"user_ad_tag":    func(u *runtimeUser) { u.UserAdTag = "" },
		"max_tcp_conns":  func(u *runtimeUser) { u.MaxTCPConns = 0 },
		"max_unique_ips": func(u *runtimeUser) { u.MaxUniqueIPs = 9 },
	} {
		changed := base
		change(&changed)
		if runtimeUserEqual(&base, &changed) {
			t.Errorf("users differing in %s compare equal", name)
		}
	}
	if runtimeUserEqual(&base, nil) || !runtimeUserEqual(nil, nil) {
		t.Error("nil handling is wrong")
	}
}

func TestAPIClientListUsersAndActiveIPs(t *testing.T) {
	api := newFakeTelemtAPI(t)
	api.set(func(f *fakeTelemtAPI) {
		f.disk = map[string]string{"u1": testSecret, "u2": testSecret}
		f.runtime = map[string]string{"u1": testSecret}
		f.activeIPs = map[string][]string{"u1": {"203.0.113.7"}}
	})
	client := newAPIClient(api.server.URL, "Bearer test")

	users, err := client.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	inRuntime := map[string]bool{}
	for _, user := range users {
		inRuntime[user.Username] = user.InRuntime
	}
	if len(users) != 2 || !inRuntime["u1"] || inRuntime["u2"] {
		t.Errorf("ListUsers = %+v, want u1 in runtime and u2 only on disk", users)
	}

	ips, err := client.ActiveIPs(context.Background())
	if err != nil {
		t.Fatalf("ActiveIPs: %v", err)
	}
	if !slices.Equal(ips["u1"], []string{"203.0.113.7"}) {
		t.Errorf("ActiveIPs = %v", ips)
	}
}
