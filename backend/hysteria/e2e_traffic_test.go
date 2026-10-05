package hysteria

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

// newTestBackend starts a real hysteria2 core through the backend, exactly the
// way the controller does.
func newTestBackend(t *testing.T, exe, serverConfig string, users []*common.User, apiPort int) *Hysteria {
	t.Helper()

	cfg, err := NewConfig(serverConfig, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	nodeCfg := config.NewTestConfig(t.TempDir(), uuid.New())
	t.Setenv(hysteriaExecutablePathEnv, exe)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	h, err := New(ctx, cfg, users, apiPort, nodeCfg)
	if err != nil {
		t.Fatalf("New backend: %v", err)
	}
	t.Cleanup(h.Shutdown)
	return h
}

// TestHysteriaTrafficCounted is the gate for this agent: a real hysteria2 client
// moves real bytes through the core the node started, and the bytes come back
// out of hysteria's own traffic stats API as a per-user counter.
//
// Modelled on backend/singbox/e2e_traffic_test.go, which does the same for
// VLESS. No traffic, no ship.
func TestHysteriaTrafficCounted(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	targetPort := startHTTPOrigin(t, 4096)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	const email = "4242"
	const password = "correct-horse-battery"

	h := newTestBackend(t, exe, serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil), []*common.User{
		{
			Email:    email,
			Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: password}},
			Inbounds: []string{},
		},
	}, apiPort)

	if !h.Started() {
		t.Fatal("core reports not started")
	}
	t.Logf("hysteria core started, version %s", h.Version())

	// A real hysteria2 client, with the right credential.
	clientPort := freePort(t)
	clientCfg := writeClientConfig(t, dir, "client.json", clientConfigJSON(
		"127.0.0.1:"+strconv.Itoa(serverPort), email+":"+password, clientPort, nil))
	clientLog := hysteriaClient(t, exe, clientCfg, clientPort, true)

	// Drive real traffic through the tunnel.
	got := httpGetViaProxy(clientPort, targetPort, 20*time.Second)
	if got == 0 {
		t.Fatalf("no traffic made it through the hysteria tunnel (expected %d bytes)\nclient log:\n%s",
			4096, tailFile(t, clientLog))
	}
	t.Logf("received %d bytes through the hysteria2 tunnel", got)

	// The per-user counter must reflect the traffic, keyed by the username.
	ctx := context.Background()
	deadline := time.Now().Add(20 * time.Second)
	var up, down int64
	seen := false
	for time.Now().Before(deadline) {
		stats, err := h.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
		if err != nil {
			t.Fatalf("GetStats: %v", err)
		}
		for _, s := range stats.GetStats() {
			if s.GetName() != email {
				continue
			}
			seen = true
			if s.GetLink() != trafficStatLink {
				t.Errorf("stat link = %q, want %q", s.GetLink(), trafficStatLink)
			}
			switch s.GetType() {
			case uplinkType:
				up = s.GetValue()
			case downlinkType:
				down = s.GetValue()
			}
		}
		if seen && (up > 0 || down > 0) {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}

	if !seen {
		t.Fatalf("no per-user stat for %q; the username must reach auth.userpass and come back as the id", email)
	}
	if up == 0 && down == 0 {
		t.Fatalf("per-user counters stayed zero after %d bytes of tunneled traffic (up=%d down=%d)", got, up, down)
	}
	t.Logf("per-user counters: uplink=%d downlink=%d", up, down)
}

// TestHysteriaWrongPasswordRefused is the negative control the scope requires:
// a client with the wrong credential must not move a byte and must not appear
// in the traffic stats.
func TestHysteriaWrongPasswordRefused(t *testing.T) {
	exe := requirePinnedBinary(t)

	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	targetPort := startHTTPOrigin(t, 4096)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	const email = "neg-control"

	h := newTestBackend(t, exe, serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil), []*common.User{
		{
			Email:    email,
			Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: "right-password"}},
			Inbounds: []string{},
		},
	}, apiPort)

	// Two wrong attempts: a wrong password and a wrong username.
	for _, badAuth := range []string{email + ":wrong-password", "nobody:right-password", "no-colon-at-all"} {
		port := freePort(t)
		clientCfg := writeClientConfig(t, dir, "bad-"+strconv.Itoa(port)+".json", clientConfigJSON(
			"127.0.0.1:"+strconv.Itoa(serverPort), badAuth, port, nil))
		// waitForProxy=false: a refused handshake means the client exits before
		// its proxy listener ever binds.
		logPath := hysteriaClient(t, exe, clientCfg, port, false)

		if got := httpGetViaProxy(port, targetPort, 3*time.Second); got != 0 {
			t.Errorf("auth %q moved %d bytes; a refused credential must move none\nclient log:\n%s",
				badAuth, got, tailFile(t, logPath))
		}
	}

	// Nothing was attributed to the user: a refused authenticate never reaches
	// the core's traffic counter.
	ctx := context.Background()
	stats, err := h.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, Reset_: true})
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	for _, s := range stats.GetStats() {
		if s.GetName() == email && (s.GetValue() > 0 || s.GetType() != uplinkType) {
			t.Errorf("refused credential produced traffic for %q: %s=%d", email, s.GetType(), s.GetValue())
		}
	}
	online, err := h.GetUserOnlineStats(ctx, email)
	if err != nil {
		t.Fatalf("GetUserOnlineStats: %v", err)
	}
	if online.GetValue() != 0 {
		t.Errorf("user %q reports %d online after only refused authentications", email, online.GetValue())
	}
}
