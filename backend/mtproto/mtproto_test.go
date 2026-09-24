package mtproto

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/pasarguard/node/common"
)

const testSecret = "00112233445566778899aabbccddeeff"

func mtUser(email, tag, secret string) *common.User {
	return &common.User{
		Email:    email,
		Inbounds: []string{tag},
		Proxies:  &common.Proxy{Mtproto: &common.Mtproto{Secret: secret}},
	}
}

func TestNewConfig_InboundTagAndValidation(t *testing.T) {
	// default inbound tag
	cfg, err := NewConfig(`{"server":{"port":2222}}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.InboundTag != defaultInboundTag {
		t.Errorf("default inbound tag = %q, want %q", cfg.InboundTag, defaultInboundTag)
	}
	if _, ok := cfg.base["inbound_tag"]; ok {
		t.Errorf("inbound_tag must be stripped from base config")
	}

	// custom inbound tag
	cfg, err = NewConfig(`{"inbound_tag":"mtp-eu","server":{"port":2222}}`)
	if err != nil {
		t.Fatalf("NewConfig returned error: %v", err)
	}
	if cfg.InboundTag != "mtp-eu" {
		t.Errorf("custom inbound tag = %q, want %q", cfg.InboundTag, "mtp-eu")
	}

	// panel must not set managed access keys
	if _, err := NewConfig(`{"access":{"users":{"a":"x"}}}`); err == nil {
		t.Errorf("expected error when panel sets access.users")
	}
	if _, err := NewConfig(`{"access":{"user_enabled":{"a":false}}}`); err == nil {
		t.Errorf("expected error when panel sets access.user_enabled")
	}

	// empty / invalid JSON
	if _, err := NewConfig("   "); err == nil {
		t.Errorf("expected error for empty config")
	}
	if _, err := NewConfig(`{`); err == nil {
		t.Errorf("expected error for invalid JSON")
	}
	if _, err := NewConfig(`{} {}`); err == nil {
		t.Errorf("expected error for trailing JSON object")
	}
}

func TestActiveUserFromCommon_Selection(t *testing.T) {
	// not tagged -> excluded, no error
	if _, include, err := activeUserFromCommon(mtUser("bob", "other", testSecret), "mtproto"); err != nil || include {
		t.Errorf("untagged user: include=%v err=%v, want include=false err=nil", include, err)
	}

	// tagged + valid secret -> included, lowercased
	u, include, err := activeUserFromCommon(mtUser("alice", "mtproto", strings.ToUpper(testSecret)), "mtproto")
	if err != nil || !include {
		t.Fatalf("valid user not included: include=%v err=%v", include, err)
	}
	if u.Username != "alice" || u.Secret != testSecret {
		t.Errorf("mapped user = %+v, want username=alice secret lowercased", u)
	}

	// tagged but missing mtproto proxy -> error
	bad := &common.User{Email: "c", Inbounds: []string{"mtproto"}, Proxies: &common.Proxy{}}
	if _, _, err := activeUserFromCommon(bad, "mtproto"); err == nil {
		t.Errorf("expected error for missing proxies.mtproto")
	}

	// invalid secret length -> error
	if _, _, err := activeUserFromCommon(mtUser("d", "mtproto", "abc"), "mtproto"); err == nil {
		t.Errorf("expected error for short secret")
	}

	// invalid username -> error
	if _, _, err := activeUserFromCommon(mtUser("has space", "mtproto", testSecret), "mtproto"); err == nil {
		t.Errorf("expected error for invalid username")
	}
}

func TestConfigRender_InjectsManagedSections(t *testing.T) {
	cfg, err := NewConfig(`{"server":{"port":2222},"censorship":{"tls_domain":"example.com"}}`)
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]*runtimeUser{"alice": {Username: "alice", Secret: testSecret}}
	out, err := cfg.Render(users, nil, 12345, 23456, "Bearer testtoken")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"enabled = true",
		`listen = "127.0.0.1:12345"`,
		`auth_header = "Bearer testtoken"`,
		`metrics_port = 23456`,
		`metrics_listen = "127.0.0.1:23456"`,
		"[access.users]",
		`alice = "` + testSecret + `"`,
		`tls_domain = "example.com"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "user_enabled") {
		t.Errorf("real users must not disable anyone via user_enabled")
	}

	// empty users + sentinel keeps telemt happy (telemt rejects empty [access.users])
	sentinel := &runtimeUser{Username: "pg-node-internal-x", Secret: testSecret}
	out, err = cfg.Render(map[string]*runtimeUser{}, sentinel, 1, 2, "")
	if err != nil {
		t.Fatalf("render with sentinel failed: %v", err)
	}
	if !strings.Contains(out, "pg-node-internal-x") {
		t.Errorf("sentinel user missing from rendered config")
	}
	if !strings.Contains(out, "[access.user_enabled]") || !strings.Contains(out, "pg-node-internal-x = false") {
		t.Errorf("sentinel must be rendered disabled, got:\n%s", out)
	}

	// empty users + no sentinel -> error (would crash telemt)
	if _, err := cfg.Render(map[string]*runtimeUser{}, nil, 1, 2, ""); err == nil {
		t.Errorf("expected error rendering with zero users and no sentinel")
	}
}

func TestTracker_DeltaResetAndCounterRestart(t *testing.T) {
	tr := newTrafficTracker()
	active := map[string]struct{}{"alice": {}}

	// telemt is always started fresh by the node, so counters begin at 0:
	// the first sample establishes the baseline and yields no delta.
	tr.Sync(map[string]userMetrics{"alice": {Uplink: 0, Downlink: 0}}, active)
	if got := tr.UsersStats("mtproto", false); len(got.Stats) != 0 {
		t.Fatalf("first sample should yield zero delta, got %+v", got.Stats)
	}

	// growth -> unreported pending delta (read without reset)
	tr.Sync(map[string]userMetrics{"alice": {Uplink: 50, Downlink: 60}}, active)
	assertDelta(t, tr.UsersStats("mtproto", false), 50, 60)

	// counter restart (telemt restarted -> counters drop): unreported 50/60 must be
	// PRESERVED, not lost, and never negative.
	tr.Sync(map[string]userMetrics{"alice": {Uplink: 5, Downlink: 3}}, active)
	assertDelta(t, tr.UsersStats("mtproto", false), 50, 60)

	// growth after restart accumulates on top of the preserved pending total
	tr.Sync(map[string]userMetrics{"alice": {Uplink: 25, Downlink: 13}}, active)
	assertDelta(t, tr.UsersStats("mtproto", true), 70, 70) // 50 preserved + (25-5); 60 + (13-3)

	// after reset with no new growth -> empty
	if got := tr.UsersStats("mtproto", false); len(got.Stats) != 0 {
		t.Fatalf("after reset with no growth, want empty, got %+v", got.Stats)
	}

	// normal post-reset growth
	tr.Sync(map[string]userMetrics{"alice": {Uplink: 35, Downlink: 20}}, active)
	assertDelta(t, tr.UsersStats("mtproto", false), 10, 7)
}

func assertDelta(t *testing.T, resp *common.StatResponse, wantUp, wantDown int64) {
	t.Helper()
	var up, down int64
	for _, s := range resp.GetStats() {
		switch s.GetType() {
		case "uplink":
			up = s.GetValue()
		case "downlink":
			down = s.GetValue()
		}
	}
	if up != wantUp || down != wantDown {
		t.Errorf("delta = up:%d down:%d, want up:%d down:%d", up, down, wantUp, wantDown)
	}
}

func TestParseMetrics(t *testing.T) {
	body := `# HELP telemt_user_octets_from_client Per-user bytes received
# TYPE telemt_user_octets_from_client counter
telemt_user_octets_from_client{user="alice"} 1024
telemt_user_octets_to_client{user="alice"} 2048
telemt_user_connections_current{user="alice"} 3
telemt_user_unique_ips_current{user="alice"} 2
telemt_stats_user_entries 1
telemt_user_octets_from_client{user="bob"} 7
`
	got, err := parseMetrics(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	alice := got["alice"]
	if alice.Uplink != 1024 || alice.Downlink != 2048 || alice.ConnectionsCurrent != 3 || alice.UniqueIPsCurrent != 2 {
		t.Errorf("alice metrics = %+v", alice)
	}
	if got["bob"].Uplink != 7 {
		t.Errorf("bob uplink = %d, want 7", got["bob"].Uplink)
	}
}

func TestGetOutboundsLatency_Empty(t *testing.T) {
	m := &MTProto{}
	resp, err := m.GetOutboundsLatency(context.Background(), &common.LatencyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || len(resp.GetLatencies()) != 0 {
		t.Errorf("expected empty latency response, got %+v", resp)
	}
}

func TestBuildPatchUserRequest_ClearsOptionalFields(t *testing.T) {
	payload, err := buildPatchUserRequest(&runtimeUser{
		Username: "alice",
		Secret:   testSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	got := string(encoded)
	for _, want := range []string{
		`"secret":"` + testSecret + `"`,
		`"user_ad_tag":null`,
		`"max_tcp_conns":null`,
		`"max_unique_ips":null`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("patch JSON missing %s: %s", want, got)
		}
	}

	tag := "aabbccddeeff00112233445566778899"
	setPayload, err := buildPatchUserRequest(&runtimeUser{
		Username:     "alice",
		Secret:       testSecret,
		UserAdTag:    tag,
		MaxTCPConns:  4,
		MaxUniqueIPs: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if setPayload.UserAdTag == nil || *setPayload.UserAdTag != tag {
		t.Errorf("user_ad_tag = %v, want %s", setPayload.UserAdTag, tag)
	}
	if setPayload.MaxTCPConns == nil || *setPayload.MaxTCPConns != 4 {
		t.Errorf("max_tcp_conns = %v, want 4", setPayload.MaxTCPConns)
	}
	if setPayload.MaxUniqueIPs == nil || *setPayload.MaxUniqueIPs != 2 {
		t.Errorf("max_unique_ips = %v, want 2", setPayload.MaxUniqueIPs)
	}
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
		process:        &processManager{cmd: &exec.Cmd{Process: &os.Process{Pid: 1}}},
		metricsScraper: newMetricsScraper("http://127.0.0.1:1/metrics"),
		tracker:        newTrafficTracker(),
		desired:        map[string]*runtimeUser{"alice": {Username: "alice", Secret: testSecret}},
	}
}
