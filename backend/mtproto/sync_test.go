package mtproto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
)

const otherSecret = "ffeeddccbbaa00112233445566778899"

// fakeTelemtAPI stands in for telemt's control API. It keeps the runtime
// user set, records every call, and runs reloads through telemt's states:
// accepted, then preparing for reloadPending polls, then a terminal state.
type fakeTelemtAPI struct {
	t          *testing.T
	server     *httptest.Server
	configPath string

	mu    sync.Mutex
	users map[string]string // runtime users: username to secret
	calls []string          // "METHOD /path" per request
	// reloadBodies holds the body of every reload request.
	reloadBodies []string

	// reloadInProgress answers this many reload requests with telemt's 409.
	reloadInProgress int
	// reloadRejectStatus, when set, answers reload requests with this status
	// and a bad_request error, like telemt for a config it cannot load.
	reloadRejectStatus int
	reloadPending      int  // status polls that report preparing first
	reloadHang         bool // the reload never finishes
	reloadState        string
	reloadError        string
	nextReloadID       int
	pendingPolls       map[int]int
	// failPatch answers PATCH requests with a 500.
	failPatch bool
	activeIPs map[string][]string
}

func newFakeTelemtAPI(t *testing.T) *fakeTelemtAPI {
	t.Helper()
	f := &fakeTelemtAPI{
		t:            t,
		configPath:   filepath.Join(t.TempDir(), "config.toml"),
		users:        make(map[string]string),
		pendingPolls: make(map[int]int),
		activeIPs:    make(map[string][]string),
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

func (f *fakeTelemtAPI) runtimeUsers() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	users := make(map[string]string, len(f.users))
	for name, secret := range f.users {
		users[name] = secret
	}
	return users
}

func (f *fakeTelemtAPI) set(apply func(f *fakeTelemtAPI)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	apply(f)
}

// loadUsersLocked reads [access.users] from the rendered config, as a
// telemt (re)start or a successful reload does.
func (f *fakeTelemtAPI) loadUsersLocked() {
	data, err := os.ReadFile(f.configPath)
	if err != nil {
		f.t.Errorf("fake telemt: reading the config: %v", err)
		return
	}
	users := make(map[string]string)
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
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
			f.t.Errorf("fake telemt: bad user line %q", line)
			continue
		}
		users[strings.Trim(strings.TrimSpace(key), `"`)] = secret
	}
	f.users = users
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
		data := []map[string]any{}
		for name := range f.users {
			data = append(data, map[string]any{"username": name, "in_runtime": true})
		}
		writeFakeSuccess(w, http.StatusOK, data)

	case r.Method == http.MethodPost && path == "/v1/users":
		var request telemtCreateUserRequest
		if err := json.Unmarshal(body, &request); err != nil {
			writeFakeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		if _, exists := f.users[request.Username]; exists {
			writeFakeError(w, http.StatusConflict, "user_exists", "User already exists")
			return
		}
		f.users[request.Username] = request.Secret
		writeFakeSuccess(w, http.StatusCreated, map[string]any{"user": map[string]any{"username": request.Username}})

	case strings.HasPrefix(path, "/v1/users/"):
		name := strings.TrimPrefix(path, "/v1/users/")
		if _, exists := f.users[name]; !exists {
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
				f.users[name] = request.Secret
			}
			writeFakeSuccess(w, http.StatusOK, map[string]any{"username": name})
		case http.MethodDelete:
			if len(f.users) == 1 {
				writeFakeError(w, http.StatusConflict, "last_user_forbidden", "Cannot delete the last user")
				return
			}
			delete(f.users, name)
			writeFakeSuccess(w, http.StatusOK, name)
		default:
			// A GET of one user loads the whole config in telemt; the node
			// must not need it.
			writeFakeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "unexpected "+r.Method)
		}

	case r.Method == http.MethodPost && path == "/v1/system/reload":
		f.reloadBodies = append(f.reloadBodies, string(body))
		if f.reloadInProgress > 0 {
			f.reloadInProgress--
			writeFakeError(w, http.StatusConflict, "reload_in_progress", "Reload 7 is already in progress")
			return
		}
		if f.reloadRejectStatus != 0 {
			writeFakeError(w, f.reloadRejectStatus, "bad_request", "invalid runtime config: bad listener")
			return
		}
		f.nextReloadID++
		f.pendingPolls[f.nextReloadID] = f.reloadPending
		writeFakeSuccess(w, http.StatusAccepted, map[string]any{
			"reload_id": f.nextReloadID, "target_generation": f.nextReloadID + 1,
			"config_revision": "r", "state": "accepted", "mode": "instant", "failure_policy": "rollback",
		})

	case r.Method == http.MethodGet && strings.HasPrefix(path, "/v1/system/reload/"):
		id, err := strconv.Atoi(strings.TrimPrefix(path, "/v1/system/reload/"))
		if _, known := f.pendingPolls[id]; err != nil || !known {
			writeFakeError(w, http.StatusNotFound, "reload_not_found", "Reload was not found")
			return
		}
		status := map[string]any{"reload_id": id, "mode": "instant", "failure_policy": "rollback"}
		switch {
		case f.reloadHang || f.pendingPolls[id] > 0:
			f.pendingPolls[id]--
			status["state"] = "preparing"
		case f.reloadState == "" || f.reloadState == "succeeded":
			f.loadUsersLocked()
			status["state"] = "succeeded"
		default:
			status["state"] = f.reloadState
			status["error"] = f.reloadError
		}
		writeFakeSuccess(w, http.StatusOK, status)

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
// process is a stand-in that counts as started, and the fake's runtime users
// are loaded from the initial render, as a telemt start would.
func newSyncTestBackend(t *testing.T, api *fakeTelemtAPI, users []*common.User) *MTProto {
	t.Helper()

	mtConfig, err := NewConfig(`{"inbound_tag": "mtproto", "server": {"port": 8443}}`)
	if err != nil {
		t.Fatal(err)
	}
	sentinel, err := newSentinelUser()
	if err != nil {
		t.Fatal(err)
	}
	desired, _ := ActiveUsersFromCommon(users, mtConfig.InboundTag)

	lifetime, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m := &MTProto{
		config:         mtConfig,
		process:        &processManager{run: &telemtRun{pid: 1, waitDone: make(chan struct{})}},
		configPath:     api.configPath,
		apiClient:      newAPIClient(api.server.URL, "Bearer test"),
		metricsScraper: newMetricsScraper("http://127.0.0.1:1/metrics"),
		tracker:        newTrafficTracker(),
		sentinel:       sentinel,
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
	api.set(func(f *fakeTelemtAPI) { f.loadUsersLocked() })
	return m
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
	if got := api.runtimeUsers()["u2"]; got != otherSecret {
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
		api.set(func(f *fakeTelemtAPI) { delete(f.users, "u2") })
		if err := m.SyncUser(ctx, mtUser("u2", "mtproto", otherSecret)); err != nil {
			t.Fatalf("SyncUser: %v", err)
		}
		assertCalls(t, api.takeCalls(), "PATCH /v1/users/u2", "POST /v1/users")
		if got := api.runtimeUsers()["u2"]; got != otherSecret {
			t.Errorf("telemt u2 secret = %q, want %q", got, otherSecret)
		}
	})

	t.Run("create of a user telemt has patches it", func(t *testing.T) {
		api.set(func(f *fakeTelemtAPI) { f.users["u4"] = testSecret })
		if err := m.SyncUser(ctx, mtUser("u4", "mtproto", otherSecret)); err != nil {
			t.Fatalf("SyncUser: %v", err)
		}
		assertCalls(t, api.takeCalls(), "POST /v1/users", "PATCH /v1/users/u4")
		if got := api.runtimeUsers()["u4"]; got != otherSecret {
			t.Errorf("telemt u4 secret = %q, want %q", got, otherSecret)
		}
	})

	t.Run("delete of a user telemt lacks succeeds", func(t *testing.T) {
		api.set(func(f *fakeTelemtAPI) { delete(f.users, "u3") })
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

	assertCalls(t, api.takeCalls(), "POST /v1/system/reload", "GET /v1/system/reload/1")
	after, err := os.Stat(api.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Error("the config was not rendered again before the reload")
	}
	runtime := api.runtimeUsers()
	if len(runtime) != partialApplyMaxUsers+2 || runtime["u33"] != numberedSecret(33) || runtime["u0"] != testSecret {
		t.Errorf("telemt users after the reload = %v, want u0 to u33", runtime)
	}
	if got := len(desiredNames(m)); got != partialApplyMaxUsers+2 {
		t.Errorf("desired has %d users, want %d", got, partialApplyMaxUsers+2)
	}
}

func TestFullSyncReportsRejectedReload(t *testing.T) {
	cases := map[string]func(f *fakeTelemtAPI) string{
		"rolled back": func(f *fakeTelemtAPI) string {
			f.reloadState, f.reloadError = "rolled_back", "bad config"
			return "bad config"
		},
		"failed": func(f *fakeTelemtAPI) string {
			f.reloadState, f.reloadError = "failed", "listener bind failed"
			return "listener bind failed"
		},
		"refused": func(f *fakeTelemtAPI) string {
			f.reloadRejectStatus = http.StatusBadRequest
			return "bad listener"
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			api := newFakeTelemtAPI(t)
			m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})
			var want string
			api.set(func(f *fakeTelemtAPI) { want = setup(f) })

			err := m.SyncUsers(context.Background(), []*common.User{mtUser("u2", "mtproto", otherSecret)})
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("SyncUsers = %v, want an error containing %q", err, want)
			}
			if got := desiredNames(m); !slices.Equal(got, []string{"u1"}) {
				t.Errorf("desired = %q after a rejected reload, want u1", got)
			}
			if !m.process.Started() {
				t.Error("a rejected reload stopped telemt")
			}
			// telemt watches the file: it must hold the confirmed users again.
			data, err := os.ReadFile(api.configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "u1 = ") || strings.Contains(string(data), "u2 = ") {
				t.Errorf("config after a rejected reload is not the previous user set:\n%s", data)
			}
		})
	}
}

func TestFullSyncRetriesReloadInProgress(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})
	api.set(func(f *fakeTelemtAPI) {
		f.reloadInProgress = 1
		f.reloadPending = 2
	})

	if err := m.SyncUsers(context.Background(), []*common.User{mtUser("u2", "mtproto", testSecret)}); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}
	assertCalls(t, api.takeCalls(),
		"POST /v1/system/reload", "POST /v1/system/reload",
		"GET /v1/system/reload/1", "GET /v1/system/reload/1", "GET /v1/system/reload/1")
	api.set(func(f *fakeTelemtAPI) {
		for _, body := range f.reloadBodies {
			if body != `{"mode":"instant","failure_policy":"rollback"}` {
				t.Errorf("reload body = %s", body)
			}
		}
	})
	if got := desiredNames(m); !slices.Equal(got, []string{"u2"}) {
		t.Errorf("desired = %q, want u2", got)
	}
	if runtime := api.runtimeUsers(); len(runtime) != 1 || runtime["u2"] == "" {
		t.Errorf("telemt users = %v, want u2", runtime)
	}
}

// TestFullSyncWithoutChangesSkipsReload: a reload cuts every telemt session,
// so a full sync of the confirmed users sends nothing; once the state is
// unconfirmed, the same sync reloads.
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
	assertCalls(t, api.takeCalls(), "POST /v1/system/reload", "GET /v1/system/reload/1")
}

func TestZeroUsersUsesSentinelPath(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})
	ctx := context.Background()

	if err := m.UpdateUsers(ctx, []*common.User{untagged("u1")}); err != nil {
		t.Fatalf("UpdateUsers to zero users: %v", err)
	}
	assertCalls(t, api.takeCalls(), "POST /v1/system/reload", "GET /v1/system/reload/1")
	if got := desiredNames(m); len(got) != 0 {
		t.Errorf("desired = %q, want none", got)
	}
	if runtime := api.runtimeUsers(); len(runtime) != 1 || runtime[m.sentinel.Username] == "" {
		t.Errorf("telemt users = %v, want only the sentinel", runtime)
	}

	if err := m.SyncUser(ctx, mtUser("u2", "mtproto", testSecret)); err != nil {
		t.Fatalf("SyncUser from zero users: %v", err)
	}
	assertCalls(t, api.takeCalls(), "POST /v1/system/reload", "GET /v1/system/reload/2")
	if runtime := api.runtimeUsers(); len(runtime) != 1 || runtime["u2"] == "" {
		t.Errorf("telemt users = %v, want only u2", runtime)
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

// TestUnconfirmedReloadForcesFullApply: the caller gives up while telemt is
// still reloading. telemt keeps running, desired keeps the confirmed users,
// and the next sync renders and reloads everything instead of a diff.
func TestUnconfirmedReloadForcesFullApply(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{
		mtUser("u1", "mtproto", testSecret),
		mtUser("u2", "mtproto", testSecret),
	})
	api.set(func(f *fakeTelemtAPI) { f.reloadHang = true })

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

	api.set(func(f *fakeTelemtAPI) { f.reloadHang = false })
	if err := m.UpdateUsers(context.Background(), []*common.User{mtUser("u2", "mtproto", otherSecret)}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	assertCalls(t, api.takeCalls(), "POST /v1/system/reload", "GET /v1/system/reload/2")
	if got := desiredNames(m); !slices.Equal(got, []string{"u1", "u2"}) {
		t.Errorf("desired = %q, want u1, u2", got)
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
	assertCalls(t, api.takeCalls(), "PATCH /v1/users/u2", "POST /v1/system/reload", "GET /v1/system/reload/1")
	if got := api.runtimeUsers()["u2"]; got != otherSecret {
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
		f.users = map[string]string{"u1": testSecret}
		f.activeIPs = map[string][]string{"u1": {"203.0.113.7"}}
	})
	client := newAPIClient(api.server.URL, "Bearer test")

	users, err := client.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Username != "u1" || !users[0].InRuntime {
		t.Errorf("ListUsers = %+v", users)
	}

	ips, err := client.ActiveIPs(context.Background())
	if err != nil {
		t.Fatalf("ActiveIPs: %v", err)
	}
	if !slices.Equal(ips["u1"], []string{"203.0.113.7"}) {
		t.Errorf("ActiveIPs = %v", ips)
	}
}
