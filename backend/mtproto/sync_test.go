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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/logstream"
)

const otherSecret = "ffeeddccbbaa00112233445566778899"
const thirdSecret = "0123456789abcdef0123456789abcdef"

var markerUsernamePattern = regexp.MustCompile(`^pgm_[0-9a-f]{16}$`)

// fakeOverride is an admission override telemt stages for a user API write.
type fakeOverride struct {
	deleted bool
	secret  string
}

// fakeTelemtAPI stands in for telemt's control API and the parts of telemt
// behind it that the node depends on:
//   - user API writes change the config file, as telemt saves them, and
//     stage an admission override that only a published config with the same
//     value clears;
//   - the config watcher publishes a changed config file when GET /v1/users
//     is polled (or connects asks), after reloadDelayPolls polls, unless
//     rejectReload is set;
//   - GET /v1/users lists the users of the config file, with in_runtime from
//     the published config.
type fakeTelemtAPI struct {
	t          *testing.T
	server     *httptest.Server
	configPath string

	mu        sync.Mutex
	runtime   map[string]string // published users: username to secret
	overrides map[string]fakeOverride
	calls     []string // "METHOD /path" per request

	rejectReload     bool
	reloadDelayPolls int
	appliedConfig    string // the config file content runtime was published from
	pendingConfig    string // a changed config file waiting to be published
	pendingPolls     int
	// rejectedConfig is the last changed config file rejectReload kept out.
	rejectedConfig string

	// loadError makes every users route fail like telemt when it cannot
	// read or parse the config file: 500 with this message.
	loadError string
	// dropUsersRequests closes this many GET /v1/users requests without an
	// answer.
	dropUsersRequests int
	failPatch         bool // PATCH answers 500
	activeIPs         map[string][]string
}

func newFakeTelemtAPI(t *testing.T) *fakeTelemtAPI {
	t.Helper()
	f := &fakeTelemtAPI{
		t:          t,
		configPath: filepath.Join(t.TempDir(), "config.toml"),
		runtime:    make(map[string]string),
		overrides:  make(map[string]fakeOverride),
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

// realRuntimeUsers returns the published users without marker users, after
// the watcher picked up the config file.
func (f *fakeTelemtAPI) realRuntimeUsers() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.watchConfigLocked()
	users := make(map[string]string)
	for name, secret := range f.runtime {
		if !strings.HasPrefix(name, markerUsernamePrefix) {
			users[name] = secret
		}
	}
	return users
}

// runtimeMarkers lists the marker users in the published config.
func (f *fakeTelemtAPI) runtimeMarkers() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.watchConfigLocked()
	var markers []string
	for name := range f.runtime {
		if strings.HasPrefix(name, markerUsernamePrefix) {
			markers = append(markers, name)
		}
	}
	return markers
}

// connects reports whether a client with secret gets past telemt's
// handshake as username: the published config and the effective admission
// state (a staged override wins) must both hold that secret. The watcher
// picks up the config file first, as time passing would.
func (f *fakeTelemtAPI) connects(username, secret string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.watchConfigLocked()
	configured, ok := f.runtime[username]
	if !ok || configured != secret {
		return false
	}
	if override, staged := f.overrides[username]; staged {
		return !override.deleted && override.secret == secret
	}
	return true
}

func (f *fakeTelemtAPI) set(apply func(f *fakeTelemtAPI)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	apply(f)
}

// startLocked publishes the config file, as a telemt start: fresh admission
// state, no overrides.
func (f *fakeTelemtAPI) startLocked() {
	data, err := os.ReadFile(f.configPath)
	if err != nil {
		f.t.Errorf("fake telemt: reading the config: %v", err)
		return
	}
	f.publishLocked(string(data))
	f.overrides = make(map[string]fakeOverride)
}

// publishLocked makes content the running config and clears the overrides
// it matches, like telemt's admission reconcile.
func (f *fakeTelemtAPI) publishLocked(content string) {
	f.runtime = parseConfigUsers(content)
	f.appliedConfig = content
	for name, override := range f.overrides {
		configured, present := f.runtime[name]
		if (override.deleted && !present) || (!override.deleted && present && configured == override.secret) {
			delete(f.overrides, name)
		}
	}
}

// watchConfigLocked plays telemt's config watcher.
func (f *fakeTelemtAPI) watchConfigLocked() {
	data, err := os.ReadFile(f.configPath)
	if err != nil || f.loadError != "" {
		return
	}
	content := string(data)
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
	f.publishLocked(content)
}

// editDiskLocked changes the users of the config file, as telemt's user API
// saves a change.
func (f *fakeTelemtAPI) editDiskLocked(edit func(users map[string]string)) {
	data, _ := os.ReadFile(f.configPath)
	users := parseConfigUsers(string(data))
	edit(users)
	if err := os.WriteFile(f.configPath, []byte(rewriteConfigUsers(string(data), users)), 0o600); err != nil {
		f.t.Errorf("fake telemt: writing the config: %v", err)
	}
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

// rewriteConfigUsers replaces the [access.users] entries of config.
func rewriteConfigUsers(config string, users map[string]string) string {
	names := make([]string, 0, len(users))
	for name := range users {
		names = append(names, name)
	}
	slices.Sort(names)
	entries := make([]string, 0, len(names))
	for _, name := range names {
		entries = append(entries, name+" = "+strconv.Quote(users[name]))
	}

	var out []string
	section, wrote := "", false
	for _, line := range strings.Split(config, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			section = strings.Trim(trimmed, "[]")
			out = append(out, line)
			if section == "access.users" {
				out = append(out, entries...)
				wrote = true
			}
			continue
		}
		if section == "access.users" && strings.Contains(trimmed, "=") {
			continue
		}
		out = append(out, line)
	}
	if !wrote {
		out = append(append(out, "[access.users]"), entries...)
	}
	return strings.Join(out, "\n") + "\n"
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

	if r.Method == http.MethodGet && path == "/v1/stats/users/active-ips" {
		type entry struct {
			Username  string   `json:"username"`
			ActiveIPs []string `json:"active_ips"`
		}
		data := []entry{}
		for name, ips := range f.activeIPs {
			data = append(data, entry{Username: name, ActiveIPs: ips})
		}
		writeFakeSuccess(w, http.StatusOK, data)
		return
	}
	if r.Method == http.MethodGet && path == "/v1/users" && f.dropUsersRequests > 0 {
		f.dropUsersRequests--
		if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
			_ = conn.Close()
		}
		return
	}
	if !strings.HasPrefix(path, "/v1/users") {
		writeFakeError(w, http.StatusNotFound, "not_found", "Route not found")
		return
	}

	// Every users route loads the config file first.
	data, err := os.ReadFile(f.configPath)
	if f.loadError != "" || err != nil {
		message := f.loadError
		if message == "" {
			message = "failed to load config: " + err.Error()
		}
		writeFakeError(w, http.StatusInternalServerError, "internal_error", message)
		return
	}
	disk := parseConfigUsers(string(data))

	switch {
	case r.Method == http.MethodGet && path == "/v1/users":
		f.watchConfigLocked()
		users := []map[string]any{}
		for name := range disk {
			_, inRuntime := f.runtime[name]
			users = append(users, map[string]any{"username": name, "in_runtime": inRuntime})
		}
		writeFakeSuccess(w, http.StatusOK, users)

	case r.Method == http.MethodPost && path == "/v1/users":
		var request telemtCreateUserRequest
		if err := json.Unmarshal(body, &request); err != nil {
			writeFakeError(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		if _, exists := disk[request.Username]; exists {
			writeFakeError(w, http.StatusConflict, "user_exists", "User already exists")
			return
		}
		f.editDiskLocked(func(users map[string]string) { users[request.Username] = request.Secret })
		f.overrides[request.Username] = fakeOverride{secret: request.Secret}
		writeFakeSuccess(w, http.StatusCreated, map[string]any{"user": map[string]any{"username": request.Username}})

	case strings.HasPrefix(path, "/v1/users/"):
		name := strings.TrimPrefix(path, "/v1/users/")
		if _, exists := disk[name]; !exists {
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
			secret := disk[name]
			if request.Secret != "" {
				secret = request.Secret
			}
			f.editDiskLocked(func(users map[string]string) { users[name] = secret })
			f.overrides[name] = fakeOverride{secret: secret}
			writeFakeSuccess(w, http.StatusOK, map[string]any{"username": name})
		case http.MethodDelete:
			if len(disk) == 1 {
				writeFakeError(w, http.StatusConflict, "last_user_forbidden", "Cannot delete the last user")
				return
			}
			f.editDiskLocked(func(users map[string]string) { delete(users, name) })
			f.overrides[name] = fakeOverride{deleted: true}
			// telemt 3.5.14 answers 202 while the running config still has
			// the user, 200 otherwise.
			_, inRuntime := f.runtime[name]
			status := http.StatusOK
			if inRuntime {
				status = http.StatusAccepted
			}
			writeFakeSuccess(w, status, map[string]any{"username": name, "in_runtime": inRuntime})
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
	m := &MTProto{
		config: mtConfig,
		process: &processManager{
			run:         &telemtRun{pid: 1, waitDone: make(chan struct{})},
			logs:        logstream.NewBuffer(100),
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
	// End a detached apply before the fake's server closes.
	t.Cleanup(func() {
		cancel()
		m.background.Wait()
	})
	if err := m.writeRenderedConfigLocked(m.desired); err != nil {
		t.Fatal(err)
	}
	api.set(func(f *fakeTelemtAPI) { f.startLocked() })
	return m
}

// waitSettled waits until no apply holds syncMu.
func waitSettled(m *MTProto) {
	m.syncMu.Lock()
	m.syncMu.Unlock()
}

// lowerMarkerConfirmTimeout sets markerConfirmTimeout for one test. Register
// it before newSyncTestBackend, so a detached apply ends before the restore.
func lowerMarkerConfirmTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	previous := markerConfirmTimeout
	markerConfirmTimeout = timeout
	t.Cleanup(func() { markerConfirmTimeout = previous })
}

// logLines returns what the backend published to telemt's log stream.
func logLines(m *MTProto) []string {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := m.SubscribeLogs(ctx)
	var lines []string
	for {
		select {
		case line := <-stream:
			lines = append(lines, line)
		default:
			return lines
		}
	}
}

// markerUsername returns the marker user of the latest render.
func (m *MTProto) markerUsername() string {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	if m.marker == nil {
		return ""
	}
	return m.marker.Username
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
	if !api.connects("u2", otherSecret) {
		t.Error("u2 cannot connect with the new secret")
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
		api.set(func(f *fakeTelemtAPI) { f.editDiskLocked(func(users map[string]string) { delete(users, "u2") }) })
		if err := m.SyncUser(ctx, mtUser("u2", "mtproto", otherSecret)); err != nil {
			t.Fatalf("SyncUser: %v", err)
		}
		assertCalls(t, api.takeCalls(), "PATCH /v1/users/u2", "POST /v1/users")
		if !api.connects("u2", otherSecret) {
			t.Error("u2 cannot connect with the new secret")
		}
	})

	t.Run("create of a user telemt has patches it", func(t *testing.T) {
		api.set(func(f *fakeTelemtAPI) { f.editDiskLocked(func(users map[string]string) { users["u4"] = testSecret }) })
		if err := m.SyncUser(ctx, mtUser("u4", "mtproto", otherSecret)); err != nil {
			t.Fatalf("SyncUser: %v", err)
		}
		assertCalls(t, api.takeCalls(), "POST /v1/users", "PATCH /v1/users/u4")
		if !api.connects("u4", otherSecret) {
			t.Error("u4 cannot connect with the new secret")
		}
	})

	t.Run("delete of a user telemt lacks succeeds", func(t *testing.T) {
		api.set(func(f *fakeTelemtAPI) { f.editDiskLocked(func(users map[string]string) { delete(users, "u3") }) })
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
// The sync fails with telemt's last output, desired is unchanged, the
// previous users are rendered again with a new marker, and the rejection
// reaches the log stream the panel shows.
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
	if lines := logLines(m); !slices.ContainsFunc(lines, func(line string) bool {
		return strings.Contains(line, "did not load the new config")
	}) {
		t.Errorf("the rejection is not in the log stream: %q", lines)
	}
}

// TestLoadFailureRejectsAtOnce: telemt cannot load the rendered file, so GET
// /v1/users answers 500 when telemt cannot read or parse the rendered file;
// that is a rejection with telemt's message, without waiting out
// markerConfirmTimeout.
func TestLoadFailureRejectsAtOnce(t *testing.T) {
	for name, message := range map[string]string{
		"parse": "failed to load config: TOML parse error at line 3",
		// telemt 3.5.14 checks its 8 MiB source limit while it reads the
		// config graph, before it parses anything.
		"read": "failed to read config graph: Config error: file exceeds configured size limit",
	} {
		t.Run(name, func(t *testing.T) {
			api := newFakeTelemtAPI(t)
			m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})
			api.set(func(f *fakeTelemtAPI) { f.loadError = message })

			started := time.Now()
			err := m.SyncUsers(context.Background(), []*common.User{mtUser("u2", "mtproto", testSecret)})
			if !errors.Is(err, errReloadRejected) || !strings.Contains(err.Error(), message) {
				t.Fatalf("SyncUsers = %v, want a rejection with telemt's message", err)
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Errorf("the rejection took %s", elapsed)
			}
			if got := desiredNames(m); !slices.Equal(got, []string{"u1"}) {
				t.Errorf("desired = %q, want u1", got)
			}
			if users := parseConfigUsers(readConfig(t, api.configPath)); users["u1"] == "" || users["u2"] != "" {
				t.Errorf("the previous users were not rendered again: %v", users)
			}
		})
	}
}

// TestCallerDeadlineDoesNotStopApply: a panel call's deadline (here 1 s)
// ends before telemt's verdict. The caller gets its ctx error at once; the
// apply goes on, finds the render rejected, renders the previous users
// again and logs telemt's reason for the panel.
func TestCallerDeadlineDoesNotStopApply(t *testing.T) {
	lowerMarkerConfirmTimeout(t, 2*time.Second)
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})
	m.process.startupTail.add("config reload rejected: bad listener")
	api.set(func(f *fakeTelemtAPI) { f.rejectReload = true })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	err := m.SyncUsers(ctx, []*common.User{mtUser("u2", "mtproto", otherSecret)})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SyncUsers = %v, want the caller's deadline", err)
	}
	// The panel matches these texts to treat the sync as retry-later.
	for _, want := range []string{"the users are still being applied", "context deadline exceeded"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("SyncUsers error %q does not contain %q", err, want)
		}
	}
	if elapsed := time.Since(started); elapsed > 1500*time.Millisecond {
		t.Errorf("the caller waited %s after its 1 s deadline", elapsed)
	}

	waitSettled(m)
	if users := parseConfigUsers(readConfig(t, api.configPath)); users["u1"] != testSecret || users["u2"] != "" {
		t.Errorf("the previous users were not rendered again: %v", users)
	}
	if got := desiredNames(m); !slices.Equal(got, []string{"u1"}) {
		t.Errorf("desired = %q, want u1", got)
	}
	if lines := logLines(m); !slices.ContainsFunc(lines, func(line string) bool {
		return strings.Contains(line, "did not load the new config") && strings.Contains(line, "bad listener")
	}) {
		t.Errorf("the rejection and telemt's reason are not in the log stream: %q", lines)
	}

	// telemt still runs the confirmed users, so the next change is a diff.
	api.set(func(f *fakeTelemtAPI) { f.rejectReload = false })
	api.takeCalls()
	if err := m.UpdateUsers(context.Background(), []*common.User{mtUser("u1", "mtproto", otherSecret)}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	assertCalls(t, api.takeCalls(), "PATCH /v1/users/u1")
}

// TestQueuedCallerGivesUpAtDeadline: a call waiting for syncMu behind a
// long apply returns its ctx error at its own deadline, not when the apply
// ends.
func TestQueuedCallerGivesUpAtDeadline(t *testing.T) {
	lowerMarkerConfirmTimeout(t, 3*time.Second)
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})
	api.set(func(f *fakeTelemtAPI) { f.rejectReload = true })

	initialMarker := m.markerUsername()
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- m.SyncUsers(context.Background(), []*common.User{mtUser("u2", "mtproto", testSecret)})
	}()
	// The first apply holds syncMu once it rendered its marker.
	deadline := time.Now().Add(5 * time.Second)
	for m.markerUsername() == initialMarker {
		if time.Now().After(deadline) {
			t.Fatal("the first apply never rendered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := m.UpdateUsers(ctx, []*common.User{mtUser("u3", "mtproto", testSecret)})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued UpdateUsers = %v, want its deadline", err)
	}
	// The panel matches this text to treat the sync as retry-later.
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("queued UpdateUsers error %q does not contain %q", err, "context deadline exceeded")
	}
	if elapsed := time.Since(started); elapsed > 1500*time.Millisecond {
		t.Errorf("the queued caller waited %s with a 500 ms deadline", elapsed)
	}
	if err := <-firstDone; !errors.Is(err, errReloadRejected) {
		t.Errorf("first SyncUsers = %v, want the rejection", err)
	}
}

// TestFullRenderClearsStaleAPIOverrides: telemt stages an admission
// override for every user API write and clears it only when a published
// config carries the same value. A full render that changes such a user
// again, before telemt published the API's own write, must first make the
// override agree, or the user is locked out.
func TestFullRenderClearsStaleAPIOverrides(t *testing.T) {
	cases := map[string]struct {
		apiChange *common.User
		render    []*common.User
		user      string
		secret    string
		calls     []string
	}{
		"patched, then changed by a render": {
			apiChange: mtUser("u2", "mtproto", otherSecret),
			render:    []*common.User{mtUser("u1", "mtproto", testSecret), mtUser("u2", "mtproto", thirdSecret)},
			user:      "u2",
			secret:    thirdSecret,
			calls:     []string{"PATCH /v1/users/u2", "PATCH /v1/users/u2", "GET /v1/users"},
		},
		"deleted, then added back by a render": {
			apiChange: untagged("u2"),
			render:    []*common.User{mtUser("u1", "mtproto", testSecret), mtUser("u2", "mtproto", thirdSecret)},
			user:      "u2",
			secret:    thirdSecret,
			calls:     []string{"DELETE /v1/users/u2", "POST /v1/users", "GET /v1/users"},
		},
		"created, then removed by a render": {
			apiChange: mtUser("u3", "mtproto", otherSecret),
			render:    []*common.User{mtUser("u1", "mtproto", testSecret), mtUser("u2", "mtproto", testSecret)},
			user:      "u3",
			calls:     []string{"POST /v1/users", "DELETE /v1/users/u3", "GET /v1/users"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			api := newFakeTelemtAPI(t)
			m := newSyncTestBackend(t, api, []*common.User{
				mtUser("u1", "mtproto", testSecret),
				mtUser("u2", "mtproto", testSecret),
			})

			// The API write and, before telemt's watcher read the file, the
			// full render.
			if err := m.SyncUser(context.Background(), tc.apiChange); err != nil {
				t.Fatalf("SyncUser: %v", err)
			}
			if err := m.SyncUsers(context.Background(), tc.render); err != nil {
				t.Fatalf("SyncUsers: %v", err)
			}
			assertCalls(t, api.takeCalls(), tc.calls...)

			if tc.secret != "" && !api.connects(tc.user, tc.secret) {
				var override fakeOverride
				api.set(func(f *fakeTelemtAPI) { override = f.overrides[tc.user] })
				t.Errorf("%s cannot connect with %s after the render (staged override %+v)", tc.user, tc.secret, override)
			}
			api.set(func(f *fakeTelemtAPI) {
				if len(f.overrides) != 0 {
					t.Errorf("overrides left after the render: %+v", f.overrides)
				}
			})
		})
	}
}

// TestSingleAPIErrorKeepsPolling: polls without an answer, fewer than
// markerUnreachablePolls in a row from a telemt that still runs, are not an
// unreachable telemt; the wait goes on and telemt is not restarted.
func TestSingleAPIErrorKeepsPolling(t *testing.T) {
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})
	api.set(func(f *fakeTelemtAPI) { f.dropUsersRequests = markerUnreachablePolls - 1 })

	if err := m.SyncUsers(context.Background(), []*common.User{mtUser("u2", "mtproto", testSecret)}); err != nil {
		t.Fatalf("SyncUsers: %v", err)
	}
	assertCalls(t, api.takeCalls(), "GET /v1/users", "GET /v1/users", "GET /v1/users")
	if !m.process.Started() {
		t.Error("telemt was stopped after failed requests")
	}
	if got := desiredNames(m); !slices.Equal(got, []string{"u2"}) {
		t.Errorf("desired = %q, want u2", got)
	}
}

// TestHungUsersAPIIsUnreachable: an API that accepts connections but never
// answers gets markerPollTimeout per poll, so markerUnreachablePolls polls
// in a row end the marker wait inside markerConfirmTimeout as an
// unreachable telemt, which reloadLocked restarts, not as a rejected config.
func TestHungUsersAPIIsUnreachable(t *testing.T) {
	lowerMarkerConfirmTimeout(t, 4*time.Second)
	api := newFakeTelemtAPI(t)
	m := newSyncTestBackend(t, api, []*common.User{mtUser("u1", "mtproto", testSecret)})

	var polls atomic.Int32
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(hung.Close)
	t.Cleanup(func() { close(release) })
	m.apiClient = newAPIClient(hung.URL, "Bearer test")

	m.syncMu.Lock()
	started := time.Now()
	err := m.waitForMarkerLocked(context.Background(), m.markerUsername())
	elapsed := time.Since(started)
	m.syncMu.Unlock()

	if err == nil || errors.Is(err, errReloadRejected) || !strings.Contains(err.Error(), "telemt API unreachable") {
		t.Fatalf("waitForMarkerLocked = %v, want telemt API unreachable", err)
	}
	if elapsed >= markerConfirmTimeout {
		t.Errorf("the wait took %s, not inside markerConfirmTimeout (%s)", elapsed, markerConfirmTimeout)
	}
	if got := polls.Load(); got != markerUnreachablePolls {
		t.Errorf("%d polls reached the API, want %d", got, markerUnreachablePolls)
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
	if !api.connects("u2", testSecret) {
		t.Error("u2 cannot connect")
	}

	// A full sync to zero users renders the marker alone; u2, last written
	// through the API, is deleted through it again first.
	if err := m.SyncUsers(ctx, nil); err != nil {
		t.Fatalf("SyncUsers to zero users: %v", err)
	}
	assertCalls(t, api.takeCalls(), "DELETE /v1/users/u2", "GET /v1/users")
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

// TestPartialFailureFallsBackToFullApply: a failed PATCH may or may not have
// reached telemt, so the full apply writes the user through the API again
// before the render. When that fails too, the render still lands, but the
// state stays unconfirmed so the next sync tries again.
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
	assertCalls(t, api.takeCalls(), "PATCH /v1/users/u2", "PATCH /v1/users/u2", "GET /v1/users")
	if !api.connects("u2", otherSecret) {
		t.Error("u2 cannot connect with the new secret")
	}
	if got := desiredSecret(m, "u2"); got != otherSecret {
		t.Errorf("desired u2 secret = %q, want %q", got, otherSecret)
	}
	m.syncMu.Lock()
	needsFullApply := m.needsFullApply
	m.syncMu.Unlock()
	if !needsFullApply {
		t.Error("a user whose API write failed twice must keep the state unconfirmed")
	}

	api.set(func(f *fakeTelemtAPI) { f.failPatch = false })
	if err := m.UpdateUsers(context.Background(), []*common.User{mtUser("u1", "mtproto", testSecret)}); err != nil {
		t.Fatalf("UpdateUsers: %v", err)
	}
	assertCalls(t, api.takeCalls(), "PATCH /v1/users/u2", "GET /v1/users")
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
		f.editDiskLocked(func(users map[string]string) {
			users["u1"] = testSecret
			users["u2"] = testSecret
		})
		data, _ := os.ReadFile(f.configPath)
		f.appliedConfig = string(data)
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

// telemt 3.5.14 answers DELETE /v1/users/{name} with an object, 202 while
// the running config still has the user. Reading it as anything else made
// every API delete look failed and fall back to a full render.
func TestAPIClientDeleteUserReadsTelemtAnswer(t *testing.T) {
	api := newFakeTelemtAPI(t)
	api.set(func(f *fakeTelemtAPI) {
		f.editDiskLocked(func(users map[string]string) {
			users["u1"] = testSecret
			users["u2"] = testSecret
		})
		f.runtime = map[string]string{"u1": testSecret, "u2": testSecret}
	})
	client := newAPIClient(api.server.URL, "Bearer test")

	if err := client.DeleteUser(context.Background(), "u1"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, onDisk := parseConfigUsers(readConfig(t, api.configPath))["u1"]; onDisk {
		t.Error("u1 is still in the config file")
	}
}
