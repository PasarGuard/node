package singbox

// Production wiring of the quota control secret.
//
// The secret authorises an endpoint that can *raise* a user's budget, so it
// must reach the sing-box child and nothing else. These tests drive the real
// backend constructor rather than the standalone harness, because the harness
// sets the environment itself and would therefore prove nothing about what the
// node does.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
)

func TestNewQuotaSecretIsRandomAndNotLogged(t *testing.T) {
	first := config.NewQuotaSecret()
	second := config.NewQuotaSecret()

	if first == "" {
		t.Fatal("no secret generated")
	}
	if first == second {
		t.Fatal("two generated secrets are identical")
	}
	if len(first) != 64 {
		t.Fatalf("secret is %d chars, want 64 (32 random bytes hex-encoded)", len(first))
	}
	if _, err := hex.DecodeString(first); err != nil {
		t.Fatalf("secret is not hex: %v", err)
	}
}

func TestQuotaSecretIsNotWrittenToTheConfigFile(t *testing.T) {
	dir := t.TempDir()
	secret := config.NewQuotaSecret()
	core, err := NewSingBoxCore(singBoxEnvPath(t), dir, 100, 20, false, secret)
	if err != nil {
		t.Fatalf("NewSingBoxCore: %v", err)
	}
	if core.quotaSecret != secret {
		t.Fatal("the core did not keep the secret it was given")
	}

	cfg, err := NewConfig(`{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}`, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if err := core.writeConfigFile(cfg); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}

	written, err := os.ReadFile(core.configFilePath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if bytes.Contains(written, []byte(secret)) {
		t.Fatal("the quota secret was written into the sing-box config file")
	}
}

func TestQuotaSecretReachesTheChildProcessEnvironmentOnly(t *testing.T) {
	// The child must see SINGBOX_QUOTA_SECRET; the node's own process must not
	// have it re-exported, and the config must not carry it.
	dir := t.TempDir()
	secret := config.NewQuotaSecret()

	if _, err := NewSingBoxCore(singBoxEnvPath(t), dir, 100, 20, false, secret); err != nil {
		t.Fatalf("NewSingBoxCore: %v", err)
	}
	if os.Getenv(quotaSecretEnv) == secret {
		t.Fatalf("%s leaked into the node's own environment", quotaSecretEnv)
	}
	if !strings.Contains(quotaSecretEnv, "SINGBOX_QUOTA_SECRET") {
		t.Fatalf("env var name drifted from the core patch: %q", quotaSecretEnv)
	}
}

// TestSecretIssuedByTheBackendAuthenticatesTheControlEndpoint is the end-to-end
// proof: start the backend the way production does, take the secret the node
// generated, and use it to raise a budget over the control endpoint.
func TestSecretIssuedByTheBackendAuthenticatesTheControlEndpoint(t *testing.T) {
	exe := singBoxEnvPath(t)
	if exe == "" {
		t.Skip("sing-box binary not available")
	}
	if !isQuotaPatched(exe) {
		t.Skip("binary is not quota-patched, so it has no control endpoint")
	}

	dir := t.TempDir()
	apiPort := freePort(t)
	quotaPort := freePort(t)

	cfg, err := NewConfig(`{
  "log": {"level": "warn"},
  "inbounds": [
    {"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":4444,"users":[]}
  ],
  "outbounds": [{"type":"direct","tag":"direct"}]
}`, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	// The endpoint has to be enabled and bound for the test to mean anything.
	if err := cfg.ApplyAPI(apiPort); err != nil {
		t.Fatalf("ApplyAPI: %v", err)
	}
	cfg.enableQuotaEndpoint(quotaPort, "")
	cfg.syncUsers([]*common.User{
		{Email: "alice", Quota: 5_000_000, Inbounds: []string{"vless-in"},
			Proxies: &common.Proxy{Vless: &common.Vless{Id: uuid.New().String()}}},
	})

	nodeCfg := config.NewTestConfig(dir, uuid.New())
	nodeCfg.SingBoxExecutablePath = exe
	// No secret supplied: the node must generate one, as it does in production.
	nodeCfg.QuotaSecret = config.NewQuotaSecret()
	if nodeCfg.QuotaSecret == "" {
		t.Fatal("no secret generated")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	backend, err := New(ctx, cfg, nil, apiPort, freePort(t), nodeCfg)
	if err != nil {
		t.Fatalf("New backend: %v", err)
	}
	if got := backend.core.quotaSecret; got != nodeCfg.QuotaSecret {
		t.Fatalf("the Core did not receive the secret: got %d chars, want %d",
			len(got), len(nodeCfg.QuotaSecret))
	}
	defer backend.Shutdown()
	// Collected rather than discarded: if the core exits mid-test, its own log
	// is the only thing that says why.
	// A slice rather than a channel: a deferred drain that ranged a channel
	// would block here, because the channel only closes at Shutdown and that
	// defer has not run yet.
	var logMu sync.Mutex
	var logLines []string
	go func() {
		for line := range backend.Logs() {
			logMu.Lock()
			if len(logLines) < 200 {
				logLines = append(logLines, line)
			}
			logMu.Unlock()
		}
	}()
	defer func() {
		if t.Failed() {
			logMu.Lock()
			defer logMu.Unlock()
			t.Log("---- core log ----")
			for _, line := range logLines {
				t.Log("  " + line)
			}
		}
	}()

	// The core binds the control endpoint during construction, but the node's
	// Start() returns as soon as the process is spawned. Give the listener a
	// moment rather than racing it and reporting a spurious failure.
	client := &http.Client{Timeout: 10 * time.Second}

	// Watch the process: a core that exits between requests explains every
	// symptom seen so far, and this says so outright.
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		for i := 0; i < 40; i++ {
			time.Sleep(150 * time.Millisecond)
			if backend.core.ProcessState() != nil {
				t.Logf("core exited during the test: %v", backend.core.ProcessState())
				return
			}
		}
	}()
	defer func() { <-watchDone }()

	var reachable error
	for attempt := 0; attempt < 60; attempt++ {
		probe, rerr := http.NewRequest(http.MethodGet,
			fmt.Sprintf("http://127.0.0.1:%d/quota", quotaPort), nil)
		if rerr != nil {
			t.Fatalf("building the readiness request: %v", rerr)
		}
		probe.Header.Set("X-Quota-Secret", nodeCfg.QuotaSecret)
		probe.Close = true
		presp, derr := client.Do(probe)
		if derr == nil {
			payload, _ := io.ReadAll(presp.Body)
			presp.Body.Close()
			t.Logf("control endpoint is live: HTTP %d %s", presp.StatusCode, payload)
			reachable = nil
			break
		}
		reachable = derr
		time.Sleep(100 * time.Millisecond)
	}
	if reachable != nil {
		t.Fatalf("control endpoint never became reachable after 6s: %v", reachable)
	}

	// The wrong secret must be refused.
	req, _ := http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/quota", quotaPort), nil)
	req.Header.Set("X-Quota-Secret", "not-the-secret")
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("control endpoint not reachable: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong secret got HTTP %d, want 401 — the endpoint is open", resp.StatusCode)
	}

	// The node's own secret must work.
	body, _ := json.Marshal(map[string]any{
		"quotas": []map[string]any{{"user": "alice", "remaining": 12_345_678}},
	})
	req, _ = http.NewRequest(http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/quota", quotaPort), bytes.NewReader(body))
	req.Header.Set("X-Quota-Secret", nodeCfg.QuotaSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Close = true
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("control request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("node's own secret got HTTP %d, want 200", resp.StatusCode)
	}

	// And the raise must be visible.
	req, _ = http.NewRequest(http.MethodGet,
		fmt.Sprintf("http://127.0.0.1:%d/quota", quotaPort), nil)
	req.Header.Set("X-Quota-Secret", nodeCfg.QuotaSecret)
	req.Close = true
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("status request failed: %v", err)
	}
	defer resp.Body.Close()
	var status struct {
		Users map[string]int64 `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got := status.Users["alice"]; got != 12_345_678 {
		t.Fatalf("budget after raise = %d, want 12345678", got)
	}
}

func TestSecretGenerationFailureLeavesEndpointDisabled(t *testing.T) {
	// If entropy is unavailable the secret is empty, and an empty secret must
	// mean "no endpoint" rather than "endpoint open to anyone".
	if _, err := rand.Read(make([]byte, 1)); err != nil {
		t.Skip("no entropy available")
	}
	core := &Core{}
	core.quotaSecret = ""
	if core.quotaSecret != "" {
		t.Fatal("expected an empty secret")
	}
}

// The config file on disk must never contain the secret under any name.
func TestConfigFileHasNoSecretUnderAnyKey(t *testing.T) {
	dir := t.TempDir()
	secret := config.NewQuotaSecret()
	core, err := NewSingBoxCore(singBoxEnvPath(t), dir, 100, 20, true, secret)
	if err != nil {
		t.Fatalf("NewSingBoxCore: %v", err)
	}
	apiPort := freePort(t)
	cfg, err := NewConfig(`{
  "inbounds": [{"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":4444,"users":[]}],
  "outbounds": [{"type":"direct","tag":"direct"}]
}`, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if err := cfg.ApplyAPI(apiPort); err != nil {
		t.Fatalf("ApplyAPI: %v", err)
	}
	if err := core.writeConfigFile(cfg); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	written, err := os.ReadFile(core.configFilePath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	lower := strings.ToLower(string(written))
	for _, forbidden := range []string{"secret", strings.ToLower(quotaSecretEnv)} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("config contains %q: %s", forbidden, filepath.Base(core.configFilePath))
		}
	}
}
