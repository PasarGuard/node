//go:build !windows

package mtproto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gopsutilprocess "github.com/shirou/gopsutil/v4/process"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
)

// Integration tests against a real telemt binary. They run only when
// MTPROTO_TELEMT_BIN points at one:
//
//	MTPROTO_TELEMT_BIN=/path/to/telemt go test ./backend/mtproto/ -run Integration -v -timeout 30m
//
// telemt binds its API only after a STUN probe and a Telegram DC check, which
// take up to about a minute on a host with slow or unreachable DCs, so each
// test runs telemt in parallel with the others and allows it
// integrationTimeout. Clients are fake (dialMTProto), and their DC is a local
// listener (startFakeDC), so no test needs Telegram.

// integrationTimeout bounds one integration test, startup included.
const integrationTimeout = 150 * time.Second

const (
	// admitWait is how long a handshake may take to show up in telemt's
	// per-user connection gauge; telemt counts it within milliseconds.
	admitWait = 5 * time.Second
	// refuseWait is how long a refused handshake must stay uncounted.
	refuseWait = 3 * time.Second
	// liveWait bounds waits for telemt to act on a change: a socket it
	// closes, a user it publishes.
	liveWait = 10 * time.Second
)

// Secrets of integration users, distinct so that a handshake names one user.
const (
	secretAlice = testSecret
	secretBob   = otherSecret
	secretCarol = thirdSecret
	secretDave  = "11111111111111111111111111111111"
	secretErin  = "22222222222222222222222222222222"
	secretOld   = "33333333333333333333333333333333"
	secretNew   = "44444444444444444444444444444444"
	secretFinal = "55555555555555555555555555555555"
)

// liveTelemt is a backend running the real telemt.
type liveTelemt struct {
	t    *testing.T
	ctx  context.Context
	mt   *MTProto
	addr string // the MTProxy listener
}

func telemtBinOrSkip(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("MTPROTO_TELEMT_BIN")
	if bin == "" {
		t.Skip("set MTPROTO_TELEMT_BIN to a telemt binary to run telemt integration tests")
	}
	return bin
}

// startLiveTelemt starts a backend on the real telemt with users, rendering
// into generatedPath (a new temp dir when empty). The test runs in parallel
// with the other integration tests.
func startLiveTelemt(t *testing.T, generatedPath string, users ...*common.User) *liveTelemt {
	t.Helper()
	return startLiveTelemtWithConfig(t, generatedPath, func(nativePort int, dc string) string {
		return fmt.Sprintf(`{
			"inbound_tag": "mtproto",
			"general": {"use_middle_proxy": false, "modes": {"classic": true, "secure": true, "tls": false}},
			"server": {"port": %d, "listeners": [{"ip": "127.0.0.1"}]},
			"dc_overrides": {"%d": %q}
		}`, nativePort, mtprotoTestDC, dc)
	}, users...)
}

// startLiveTelemtWithConfig is startLiveTelemt with the panel config built by
// configJSON from the MTProxy listener port and the fake DC address. The
// config must serve MTProxy on 127.0.0.1:nativePort.
func startLiveTelemtWithConfig(t *testing.T, generatedPath string, configJSON func(nativePort int, dc string) string, users ...*common.User) *liveTelemt {
	t.Helper()
	bin := telemtBinOrSkip(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	t.Cleanup(cancel)
	if generatedPath == "" {
		generatedPath = t.TempDir()
	}

	port := netutil.FindFreePort()
	mtConfig, err := NewConfig(configJSON(port, startFakeDC(t)))
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	nodeConfig := &config.Config{
		TelemtExecutablePath: bin,
		GeneratedConfigPath:  generatedPath,
		LogBufferSize:        1000,
	}

	started := time.Now()
	mt, err := New(ctx, nodeConfig, mtConfig, users)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(mt.Shutdown)
	t.Logf("telemt %s ready after %s", mt.Version(), time.Since(started).Round(time.Millisecond))

	return &liveTelemt{t: t, ctx: ctx, mt: mt, addr: fmt.Sprintf("127.0.0.1:%d", port)}
}

// users returns GET /v1/users by username: the users of the config file,
// with InRuntime telling whether telemt's running config has them too.
func (l *liveTelemt) users() map[string]telemtUserInfo {
	l.t.Helper()
	listed, err := l.mt.apiClient.ListUsers(l.ctx)
	if err != nil {
		l.t.Fatalf("ListUsers: %v", err)
	}
	users := make(map[string]telemtUserInfo, len(listed))
	for _, user := range listed {
		users[user.Username] = user
	}
	return users
}

// waitListed waits until the config file and the running config both have
// username, or the config file lacks it. A user missing from the file may
// still run, so absence must also be checked with expectRefused.
func (l *liveTelemt) waitListed(username string, listed bool) {
	l.t.Helper()
	waitFor(l.t, liveWait, fmt.Sprintf("telemt to list %s = %v", username, listed), func() bool {
		user, found := l.users()[username]
		if listed {
			return found && user.InRuntime
		}
		return !found
	})
}

// connections reads telemt_user_connections_current for username.
func (l *liveTelemt) connections(username string) int64 {
	l.t.Helper()
	users, _, err := l.mt.metricsScraper.Scrape(l.ctx)
	if err != nil {
		l.t.Fatalf("scrape telemt metrics: %v", err)
	}
	return users[username].ConnectionsCurrent
}

func (l *liveTelemt) waitConnections(username string, want int64) {
	l.t.Helper()
	waitFor(l.t, liveWait, fmt.Sprintf("%d telemt connections of %s", want, username), func() bool {
		return l.connections(username) == want
	})
}

func (l *liveTelemt) dial(secret string) net.Conn {
	l.t.Helper()
	conn, err := dialMTProto(l.addr, secret)
	if err != nil {
		l.t.Fatalf("dial telemt: %v", err)
	}
	l.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// expectAdmitted opens a client session of username with secret and waits
// until telemt counts it, redialling while a change telemt confirmed is
// still being published to its handshake path. It returns the open session.
func (l *liveTelemt) expectAdmitted(username, secret string) net.Conn {
	l.t.Helper()
	deadline := time.Now().Add(liveWait)
	for {
		before := l.connections(username)
		conn := l.dial(secret)
		admitted := waitUntil(admitWait, func() bool { return l.connections(username) > before })
		if admitted && !connClosed(conn, 100*time.Millisecond) {
			return conn
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			l.t.Fatalf("telemt did not admit %s with secret %s", username, secret)
		}
	}
}

// expectRefused checks that telemt stops admitting clients of username with
// secret within liveWait: a change telemt confirmed may take a moment to
// reach its handshake path. telemt keeps a refused socket open (it relays
// it to the mask host), so only its connection gauge tells.
func (l *liveTelemt) expectRefused(username, secret string) {
	l.t.Helper()
	deadline := time.Now().Add(liveWait)
	for {
		before := l.connections(username)
		conn := l.dial(secret)
		admitted := waitUntil(refuseWait, func() bool { return l.connections(username) > before })
		_ = conn.Close()
		if !admitted {
			return
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("telemt still admits %s with secret %s", username, secret)
		}
		l.waitConnections(username, before)
	}
}

// expectCut waits until telemt closed session, a client of username, and no
// longer counts any connection of username.
func (l *liveTelemt) expectCut(session net.Conn, username string) {
	l.t.Helper()
	waitFor(l.t, liveWait, fmt.Sprintf("telemt to close the session of %s", username), func() bool {
		return connClosed(session, 100*time.Millisecond)
	})
	l.waitConnections(username, 0)
}

// expectOpen checks that session is still open and that telemt counts
// connections sessions of username.
func (l *liveTelemt) expectOpen(session net.Conn, username string, connections int64) {
	l.t.Helper()
	if connClosed(session, time.Second) {
		l.t.Fatalf("telemt closed the session of %s", username)
	}
	if got := l.connections(username); got != connections {
		l.t.Fatalf("telemt counts %d connections of %s, want %d", got, username, connections)
	}
}

// expectNewMarker checks that the latest render carries a marker other than
// previous and that telemt runs it, and returns it.
func (l *liveTelemt) expectNewMarker(previous string) string {
	l.t.Helper()
	marker := l.mt.markerUsername()
	if !markerUsernamePattern.MatchString(marker) || marker == previous {
		l.t.Fatalf("marker after a render = %q, previous %q", marker, previous)
	}
	l.waitListed(marker, true)
	return marker
}

func (l *liveTelemt) expectPID(want int) {
	l.t.Helper()
	if got := l.mt.process.PID(); got != want {
		l.t.Fatalf("telemt pid = %d, want %d (telemt was restarted)", got, want)
	}
}

// waitHandlesSIGHUP waits until the node may send telemt SIGHUP (telemt
// installed its handler, or telemtSignalGrace passed where the node cannot
// tell), so the next reload sends SIGHUP instead of leaving the change to
// telemt's config watcher.
func (l *liveTelemt) waitHandlesSIGHUP() {
	l.t.Helper()
	waitFor(l.t, telemtSignalGrace+liveWait, "telemt to handle SIGHUP", func() bool {
		l.mt.syncMu.Lock()
		defer l.mt.syncMu.Unlock()
		return l.mt.telemtHandlesSIGHUPLocked()
	})
}

// sighups counts the SIGHUP reloads telemt logged.
func (l *liveTelemt) sighups() int {
	count := 0
	for _, line := range logLines(l.mt) {
		if strings.Contains(line, "SIGHUP received") {
			count++
		}
	}
	return count
}

// waitUntil polls cond every 100 ms for up to timeout and reports whether
// it held.
func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestIntegrationLifecycle(t *testing.T) {
	l := startLiveTelemt(t, "", mtUser("alice", "mtproto", secretAlice))
	mt := l.mt

	if got := mt.Version(); got != "3.5.14" {
		t.Errorf("Version() = %q, want 3.5.14", got)
	}
	if !mt.Started() {
		t.Fatal("Started() = false")
	}
	if err := mt.apiClient.Health(l.ctx); err != nil {
		t.Fatalf("telemt health: %v", err)
	}
	pid := mt.process.PID()
	if pid == 0 {
		t.Fatal("no telemt pid")
	}

	l.waitListed("alice", true)
	l.expectAdmitted("alice", secretAlice)

	// Stats read the live telemt: one client address, the client's uplink
	// bytes, then nothing new after a reset.
	if online, err := mt.GetUserOnlineStats(l.ctx, "alice"); err != nil || online.GetValue() != 1 {
		t.Errorf("GetUserOnlineStats(alice) = %v, %v; want 1 unique IP", online, err)
	}
	ips, err := mt.GetUserOnlineIpListStats(l.ctx, "alice")
	if err != nil {
		t.Fatalf("GetUserOnlineIpListStats: %v", err)
	}
	if _, found := ips.GetIps()["127.0.0.1"]; !found || len(ips.GetIps()) != 1 {
		t.Errorf("GetUserOnlineIpListStats(alice) = %v, want only 127.0.0.1", ips.GetIps())
	}
	var uplink int64
	waitFor(t, liveWait, "alice's uplink in the user stats", func() bool {
		stats, err := mt.GetStats(l.ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
		if err != nil {
			t.Fatalf("GetStats: %v", err)
		}
		for _, stat := range stats.GetStats() {
			if stat.GetName() == "alice" && stat.GetType() == "uplink" && stat.GetLink() == "mtproto" {
				uplink += stat.GetValue()
			}
		}
		return uplink > 0
	})
	time.Sleep(statsSnapshotMaxAge)
	if stats, err := mt.GetStats(l.ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true}); err != nil || len(stats.GetStats()) != 0 {
		t.Errorf("user stats after a reset = %v, %v; want none", stats.GetStats(), err)
	}
	if sys, err := mt.GetSysStats(l.ctx); err != nil || sys.GetAlloc() == 0 {
		t.Errorf("GetSysStats = %v, %v; want telemt's memory", sys, err)
	}

	configPath := mt.configPath
	mt.Shutdown()
	if _, err := os.Stat(configPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config.toml after Shutdown: %v, want it removed", err)
	}
	if exists, err := gopsutilprocess.PidExists(int32(pid)); err != nil || exists {
		t.Errorf("telemt pid %d exists after Shutdown: %v, %v", pid, exists, err)
	}
	processes, err := gopsutilprocess.Processes()
	if err != nil {
		t.Fatalf("list processes: %v", err)
	}
	for _, proc := range processes {
		if args, err := proc.CmdlineSlice(); err == nil && runsTelemtConfig(args, configPath) {
			t.Errorf("telemt process %d still runs %s after Shutdown", proc.Pid, configPath)
		}
	}
}

// User create, secret change and delete through UpdateUsers go through
// telemt's user API (the marker never changes) and reach telemt's handshake
// path, not only its config file.
func TestIntegrationUpdateUsersThroughAPI(t *testing.T) {
	l := startLiveTelemt(t, "", mtUser("alice", "mtproto", secretAlice))
	marker := l.mt.markerUsername()

	if err := l.mt.UpdateUsers(l.ctx, []*common.User{mtUser("bob", "mtproto", secretOld)}); err != nil {
		t.Fatalf("UpdateUsers(create bob): %v", err)
	}
	l.waitListed("bob", true)
	session := l.expectAdmitted("bob", secretOld)
	_ = session.Close()
	l.waitConnections("bob", 0)

	if err := l.mt.UpdateUsers(l.ctx, []*common.User{mtUser("bob", "mtproto", secretNew)}); err != nil {
		t.Fatalf("UpdateUsers(patch bob): %v", err)
	}
	session = l.expectAdmitted("bob", secretNew)
	_ = session.Close()
	l.waitConnections("bob", 0)
	l.expectRefused("bob", secretOld)

	if err := l.mt.UpdateUsers(l.ctx, []*common.User{untagged("bob")}); err != nil {
		t.Fatalf("UpdateUsers(delete bob): %v", err)
	}
	l.waitListed("bob", false)
	l.expectRefused("bob", secretNew)

	if got := l.mt.markerUsername(); got != marker {
		t.Errorf("marker changed from %s to %s: a user API batch rendered the config", marker, got)
	}
	l.expectAdmitted("alice", secretAlice)
}

// Full syncs hot-reload the same telemt process, down to zero real users
// (marker only) and back, and telemt confirms each render's marker. The
// first syncs come right after the start, when telemt may not handle SIGHUP
// yet and its config watcher reloads; the last one comes once telemt
// handles SIGHUP and sends it.
func TestIntegrationFullSyncKeepsProcess(t *testing.T) {
	l := startLiveTelemt(t, "", mtUser("alice", "mtproto", secretAlice))
	pid := l.mt.process.PID()
	marker := l.mt.markerUsername()

	err := l.mt.SyncUsers(l.ctx, []*common.User{
		mtUser("carol", "mtproto", secretCarol),
		mtUser("dave", "mtproto", secretDave),
	})
	if err != nil {
		t.Fatalf("SyncUsers(carol, dave): %v", err)
	}
	marker = l.expectNewMarker(marker)
	l.expectPID(pid)
	l.waitListed("carol", true)
	l.waitListed("dave", true)
	l.waitListed("alice", false)
	l.expectAdmitted("carol", secretCarol)
	l.expectRefused("alice", secretAlice)

	if err := l.mt.SyncUsers(l.ctx, nil); err != nil {
		t.Fatalf("SyncUsers(no users): %v", err)
	}
	marker = l.expectNewMarker(marker)
	l.expectPID(pid)
	if users := l.users(); len(users) != 1 {
		t.Errorf("telemt users after syncing none = %v, want only the marker %s", users, marker)
	}
	l.expectRefused("dave", secretDave)

	l.waitHandlesSIGHUP()
	sighups := l.sighups()
	if err := l.mt.SyncUsers(l.ctx, []*common.User{mtUser("erin", "mtproto", secretErin)}); err != nil {
		t.Fatalf("SyncUsers(erin): %v", err)
	}
	l.expectNewMarker(marker)
	if l.sighups() <= sighups {
		t.Error("telemt logged no SIGHUP for a sync once it handled SIGHUP")
	}
	l.expectPID(pid)
	l.expectAdmitted("erin", secretErin)
}

// A hot reload keeps the sessions of users it does not change and cuts the
// sessions of users it removes, right after the start (telemt's config
// watcher reloads, or SIGHUP if telemt handles it already) and once telemt
// handles SIGHUP (SIGHUP reloads).
func TestIntegrationHotReloadKeepsUnchangedSessions(t *testing.T) {
	alice := mtUser("alice", "mtproto", secretAlice)
	carol := mtUser("carol", "mtproto", secretCarol)
	l := startLiveTelemt(t, "", alice, mtUser("bob", "mtproto", secretBob))
	pid := l.mt.process.PID()

	aliceSession := l.expectAdmitted("alice", secretAlice)
	bobSession := l.expectAdmitted("bob", secretBob)
	if err := l.mt.SyncUsers(l.ctx, []*common.User{alice, carol}); err != nil {
		t.Fatalf("SyncUsers without bob: %v", err)
	}
	l.expectCut(bobSession, "bob")
	l.expectOpen(aliceSession, "alice", 1)
	l.expectPID(pid)

	carolSession := l.expectAdmitted("carol", secretCarol)
	l.waitHandlesSIGHUP()
	sighups := l.sighups()
	if err := l.mt.SyncUsers(l.ctx, []*common.User{alice, mtUser("dave", "mtproto", secretDave)}); err != nil {
		t.Fatalf("SyncUsers without carol: %v", err)
	}
	if l.sighups() <= sighups {
		t.Error("telemt logged no SIGHUP for a sync once it handled SIGHUP")
	}
	l.expectCut(carolSession, "carol")
	l.expectOpen(aliceSession, "alice", 1)
	l.expectPID(pid)
	l.expectAdmitted("dave", secretDave)
}

// A user deleted through the API loses its open session, and deleting the
// last real user leaves telemt running with only the marker.
func TestIntegrationAPIDeleteCutsSessions(t *testing.T) {
	l := startLiveTelemt(t, "", mtUser("alice", "mtproto", secretAlice), mtUser("bob", "mtproto", secretBob))
	pid := l.mt.process.PID()
	marker := l.mt.markerUsername()

	bobSession := l.expectAdmitted("bob", secretBob)
	if err := l.mt.UpdateUsers(l.ctx, []*common.User{untagged("bob")}); err != nil {
		t.Fatalf("UpdateUsers(delete bob): %v", err)
	}
	l.expectCut(bobSession, "bob")

	aliceSession := l.expectAdmitted("alice", secretAlice)
	if err := l.mt.UpdateUsers(l.ctx, []*common.User{untagged("alice")}); err != nil {
		t.Fatalf("UpdateUsers(delete the last real user): %v", err)
	}
	l.expectCut(aliceSession, "alice")
	users := l.users()
	if _, found := users[marker]; !found || len(users) != 1 || l.mt.markerUsername() != marker {
		t.Errorf("telemt users after deleting the last real user = %v, want only the marker %s", users, marker)
	}
	l.expectPID(pid)
	if err := l.mt.apiClient.Health(l.ctx); err != nil {
		t.Fatalf("telemt health with only the marker: %v", err)
	}
	l.expectRefused("alice", secretAlice)

	if err := l.mt.UpdateUsers(l.ctx, []*common.User{mtUser("carol", "mtproto", secretCarol)}); err != nil {
		t.Fatalf("UpdateUsers(create carol): %v", err)
	}
	l.expectAdmitted("carol", secretCarol)
}

// Starting with no real users runs telemt on the marker alone, and users
// added later through the API connect.
func TestIntegrationStartWithoutUsers(t *testing.T) {
	l := startLiveTelemt(t, "")

	marker := l.mt.markerUsername()
	if users := l.users(); len(users) != 1 || !users[marker].InRuntime {
		t.Fatalf("telemt users = %v, want only the marker %s", users, marker)
	}
	if err := l.mt.UpdateUsers(l.ctx, []*common.User{mtUser("alice", "mtproto", secretAlice)}); err != nil {
		t.Fatalf("UpdateUsers(alice): %v", err)
	}
	l.expectAdmitted("alice", secretAlice)
}

// A secret written through the API and changed again by a full render before
// telemt published it must not lock the user out: telemt admits the user
// with the rendered secret only.
func TestIntegrationRenderAfterAPIWriteAdmitsRenderedSecret(t *testing.T) {
	l := startLiveTelemt(t, "", mtUser("alice", "mtproto", secretAlice), mtUser("bob", "mtproto", secretOld))
	marker := l.mt.markerUsername()

	if err := l.mt.SyncUser(l.ctx, mtUser("bob", "mtproto", secretNew)); err != nil {
		t.Fatalf("SyncUser(bob, new secret): %v", err)
	}
	batch := []*common.User{mtUser("bob", "mtproto", secretFinal)}
	for i := range partialApplyMaxUsers {
		batch = append(batch, mtUser(fmt.Sprintf("u%d", i), "mtproto", numberedSecret(i)))
	}
	if err := l.mt.UpdateUsers(l.ctx, batch); err != nil {
		t.Fatalf("UpdateUsers(%d changes): %v", len(batch), err)
	}
	l.expectNewMarker(marker)

	l.expectAdmitted("bob", secretFinal)
	l.expectRefused("bob", secretNew)
	l.expectRefused("bob", secretOld)
	l.expectAdmitted("u0", numberedSecret(0))
}

// GeneratedConfigPath may be a symlink: telemt refuses a config path with a
// symlinked component, so the node renders into the resolved directory.
func TestIntegrationSymlinkedGeneratedPath(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	l := startLiveTelemt(t, link, mtUser("alice", "mtproto", secretAlice))
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(resolved, "telemt", "config.toml"); l.mt.configPath != want {
		t.Errorf("config path = %s, want %s", l.mt.configPath, want)
	}
	l.expectAdmitted("alice", secretAlice)

	marker := l.mt.markerUsername()
	if err := l.mt.SyncUsers(l.ctx, []*common.User{mtUser("bob", "mtproto", secretBob)}); err != nil {
		t.Fatalf("SyncUsers(bob): %v", err)
	}
	l.expectNewMarker(marker)
	l.expectAdmitted("bob", secretBob)
}

// rejectedRenderUsers is enough users to push the rendered config past
// telemt's 8 MiB limit for one config source; each renders as a line of
// about 45 bytes. The node itself accepts every one of them.
const rejectedRenderUsers = 220_000

// A render telemt refuses is reported with telemt's reason, and the previous
// users are rendered again: telemt keeps running them, sessions included.
func TestIntegrationRejectedRenderRestoresUsers(t *testing.T) {
	alice := mtUser("alice", "mtproto", secretAlice)
	l := startLiveTelemt(t, "", alice)
	pid := l.mt.process.PID()
	marker := l.mt.markerUsername()
	aliceSession := l.expectAdmitted("alice", secretAlice)

	users := []*common.User{alice}
	for i := range rejectedRenderUsers {
		users = append(users, mtUser(fmt.Sprint(1_000_000+i), "mtproto", fmt.Sprintf("%032x", 1_000_000+i)))
	}
	started := time.Now()
	err := l.mt.SyncUsers(l.ctx, users)
	const reason = "exceeds configured size limit"
	if !errors.Is(err, errReloadRejected) || !strings.Contains(err.Error(), reason) {
		t.Fatalf("SyncUsers(%d users) = %v, want a rejection with telemt's reason %q", len(users), err, reason)
	}
	// telemt's answer rejects the render; the node must not wait out
	// markerConfirmTimeout.
	if elapsed := time.Since(started); elapsed >= markerConfirmTimeout/2 {
		t.Errorf("the rejection took %s", elapsed)
	}
	if !slices.ContainsFunc(logLines(l.mt), func(line string) bool {
		return strings.Contains(line, reason) && strings.Contains(line, "rendering the previous users again")
	}) {
		t.Errorf("telemt's log stream has no rejection notice with its reason")
	}

	if got := desiredNames(l.mt); !slices.Equal(got, []string{"alice"}) {
		t.Errorf("desired users after the rejection = %v, want [alice]", got)
	}
	l.expectNewMarker(marker)
	l.expectPID(pid)
	if info, err := os.Stat(l.mt.configPath); err != nil || info.Size() > 1<<20 {
		t.Errorf("config file after the restore: %v, %v; want the small previous render", info, err)
	}
	l.expectOpen(aliceSession, "alice", 1)
	l.expectAdmitted("alice", secretAlice)
	l.expectRefused("1000000", fmt.Sprintf("%032x", 1_000_000))
}

// webVhostHost is the vhost of the WEB integration tests; requests name it
// in their Host header.
const webVhostHost = "proxy.example.com"

// webDecoyBody is what the WEB tests' decoy upstream answers.
const webDecoyBody = "decoy-ok"

// startLiveWebTelemt starts the real telemt with an MTProxy listener and a
// WEB listener on 127.0.0.1, one vhost for webVhostHost and a decoy upstream
// on 127.0.0.1 answering webDecoyBody. It returns the backend and the WEB
// listener address.
func startLiveWebTelemt(t *testing.T, users ...*common.User) (*liveTelemt, string) {
	t.Helper()
	telemtBinOrSkip(t)
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, webDecoyBody)
	}))
	t.Cleanup(decoy.Close)
	webPort := netutil.FindFreePort()

	l := startLiveTelemtWithConfig(t, "", func(nativePort int, dc string) string {
		return fmt.Sprintf(`{
			"inbound_tag": "mtproto",
			"general": {"use_middle_proxy": false, "modes": {"classic": true, "secure": true, "tls": false}},
			"server": {"port": %d, "listeners": [
				{"ip": "127.0.0.1"},
				{"ip": "127.0.0.1", "port": %d, "transport": "web", "web_trusted_proxy_cidrs": ["127.0.0.1/32"]}
			]},
			"dc_overrides": {"%d": %q},
			"web": {"enabled": true, "vhosts": [{
				"host": %q,
				"public_addr": "127.0.0.1:443",
				"decoy": {"mode": "http_upstream", "upstream": %q}
			}]}
		}`, nativePort, webPort, mtprotoTestDC, dc, webVhostHost, decoy.URL)
	}, users...)
	return l, fmt.Sprintf("127.0.0.1:%d", webPort)
}

// webProfileUsers returns the users of the WEB profiles telemt reports for
// webVhostHost in GET /v1/config.
func (l *liveTelemt) webProfileUsers() []string {
	l.t.Helper()
	type configData struct {
		Web struct {
			Vhosts []struct {
				Host     string `json:"host"`
				Profiles []struct {
					User string `json:"user"`
				} `json:"profiles"`
			} `json:"vhosts"`
		} `json:"web"`
	}
	data, err := doAPIRequest[configData](l.ctx, l.mt.apiClient, http.MethodGet, "/v1/config", nil)
	if err != nil {
		l.t.Fatalf("GET /v1/config: %v", err)
	}
	var users []string
	for _, vhost := range data.Web.Vhosts {
		if vhost.Host != webVhostHost {
			continue
		}
		for _, profile := range vhost.Profiles {
			users = append(users, profile.User)
		}
	}
	slices.Sort(users)
	return users
}

// waitWebProfileUsers waits until telemt reports WEB profiles for exactly
// want, sorted.
func (l *liveTelemt) waitWebProfileUsers(want ...string) {
	l.t.Helper()
	var got []string
	if !waitUntil(liveWait, func() bool {
		got = l.webProfileUsers()
		return slices.Equal(got, want)
	}) {
		l.t.Fatalf("telemt WEB profiles of %s = %v, want %v", webVhostHost, got, want)
	}
}

// A WEB listener relays a plain request for the vhost to the decoy, telemt
// runs one WEB profile per user and follows a full sync, and a native
// session stays open across that sync.
func TestIntegrationWebDecoyAndProfiles(t *testing.T) {
	u1 := mtUser("u1", "mtproto", secretAlice)
	l, webAddr := startLiveWebTelemt(t, u1)

	request, err := http.NewRequestWithContext(l.ctx, http.MethodGet, "http://"+webAddr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = webVhostHost
	request.Header.Set("X-Forwarded-For", "198.51.100.7")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET / on the WEB listener: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != webDecoyBody {
		t.Fatalf("GET / on the WEB listener = %d %q, %v; want 200 %q from the decoy", response.StatusCode, body, err, webDecoyBody)
	}
	t.Logf("WEB listener answered %d %q", response.StatusCode, body)

	l.waitWebProfileUsers("u1")
	session := l.expectAdmitted("u1", secretAlice)

	if err := l.mt.SyncUsers(l.ctx, []*common.User{u1, mtUser("u2", "mtproto", secretBob)}); err != nil {
		t.Fatalf("SyncUsers(u1, u2): %v", err)
	}
	l.waitWebProfileUsers("u1", "u2")
	t.Logf("telemt WEB profiles after the sync: %v", l.webProfileUsers())
	l.expectOpen(session, "u1", 1)
	l.expectAdmitted("u2", secretBob)
}

// With no real users, telemt starts with WEB on and the marker's profile as
// the only one.
func TestIntegrationWebStartWithoutUsers(t *testing.T) {
	l, _ := startLiveWebTelemt(t)

	marker := l.mt.markerUsername()
	l.waitWebProfileUsers(marker)
	t.Logf("telemt WEB profiles without users: %v", l.webProfileUsers())
}
