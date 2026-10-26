package mtproto

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/pasarguard/node/common"
)

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

func TestNewConfigRejectsNodeManagedKeys(t *testing.T) {
	cases := []struct {
		raw string
		key string
	}{
		{`{"include": "x"}`, "include"},
		{`{"general": {"include": "x"}}`, "general.include"},
		{`{"server": {"listeners": [{"ip": "::", "include": "x"}]}}`, "server.listeners[0].include"},
		{`{"server": {"api": {"read_only": true}}}`, "server.api"},
		{`{"server": {"admin_api": {}}}`, "server.admin_api"},
		{`{"server": {"metrics_port": 1}}`, "server.metrics_port"},
		{`{"server": {"metrics_listen": "0.0.0.0:9090"}}`, "server.metrics_listen"},
		{`{"server": {"metrics_whitelist": ["0.0.0.0/0"]}}`, "server.metrics_whitelist"},
		{`{"access": {"user_rate_limits": {}}}`, "access.user_rate_limits"},
		{`{"access": {"user_source_deny": {}}}`, "access.user_source_deny"},
		{`{"access": {"users": {}}}`, "access.users"},
		{`{"access": {"user_ad_tags": {}}}`, "access.user_ad_tags"},
		{`{"access": {"user_max_tcp_conns": {}}}`, "access.user_max_tcp_conns"},
		{`{"access": {"user_expirations": {}}}`, "access.user_expirations"},
		{`{"access": {"user_data_quota": {}}}`, "access.user_data_quota"},
		{`{"access": {"user_max_unique_ips": {}}}`, "access.user_max_unique_ips"},
		{`{"access": {"user_enabled": {}}}`, "access.user_enabled"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			_, err := NewConfig(tc.raw)
			if err == nil {
				t.Fatalf("NewConfig(%s) succeeded, want an error naming %s", tc.raw, tc.key)
			}
			if !strings.Contains(err.Error(), "must not define "+tc.key) {
				t.Errorf("error %q does not name %s", err, tc.key)
			}
		})
	}

	// An empty web object is not enabled and needs no listener.
	if _, err := NewConfig(`{"web": {}}`); err != nil {
		t.Errorf("an empty web object must be accepted, got %v", err)
	}

	// Keys that only share a prefix with a rejected one stay allowed.
	if _, err := NewConfig(`{"server": {"port": 443, "listen_backlog": 128}, "access": {"replay_check_len": 65536}}`); err != nil {
		t.Errorf("unrelated keys must be accepted, got %v", err)
	}
}

func TestNewConfigValidatesShapes(t *testing.T) {
	cases := map[string]string{
		"general not object":    `{"general": 1}`,
		"telemetry not object":  `{"general": {"telemetry": true}}`,
		"server not object":     `{"server": []}`,
		"access not object":     `{"access": "x"}`,
		"logging not object":    `{"logging": "file"}`,
		"port zero":             `{"server": {"port": 0}}`,
		"port too large":        `{"server": {"port": 65536}}`,
		"port string":           `{"server": {"port": "443"}}`,
		"port fraction":         `{"server": {"port": 443.5}}`,
		"listeners not array":   `{"server": {"listeners": {"ip": "::"}}}`,
		"listener not object":   `{"server": {"listeners": [1]}}`,
		"listener port invalid": `{"server": {"listeners": [{"ip": "::", "port": -1}]}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewConfig(raw); err == nil {
				t.Errorf("NewConfig(%s) succeeded, want an error", raw)
			}
		})
	}

	// JSON null means "not set" for objects and ports.
	if _, err := NewConfig(`{"general": null, "server": {"port": null, "api": null}, "access": null}`); err != nil {
		t.Errorf("null sections must be treated as absent, got %v", err)
	}
}

func TestNewConfigRejectsNonMTProxyListeners(t *testing.T) {
	cases := map[string]string{
		"socks":      `{"server": {"listeners": [{"ip": "::", "transport": "socks"}]}}`,
		"upper case": `{"server": {"listeners": [{"ip": "::"}, {"ip": "0.0.0.0", "transport": "WEB"}]}}`,
		"not string": `{"server": {"listeners": [{"ip": "::", "transport": 1}]}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewConfig(raw)
			if err == nil {
				t.Fatalf("NewConfig(%s) succeeded, want an error", raw)
			}
			if !strings.Contains(err.Error(), "server.listeners[") || !strings.Contains(err.Error(), "].transport") {
				t.Errorf("error %q does not name the listener transport key", err)
			}
		})
	}

	for _, raw := range []string{
		`{"server": {"listeners": [{"ip": "::", "transport": "mtproxy"}]}}`,
		`{"server": {"listeners": [{"ip": "::", "transport": null}, {"ip": "0.0.0.0"}]}}`,
	} {
		if _, err := NewConfig(raw); err != nil {
			t.Errorf("NewConfig(%s) failed: %v", raw, err)
		}
	}
}

func TestConfigListenPorts(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []int
	}{
		{"telemt default port", `{}`, []int{443}},
		{"server port", `{"server": {"port": 2222}}`, []int{2222}},
		{
			"listeners with and without port",
			`{"server": {"port": 8443, "listeners": [{"ip": "0.0.0.0"}, {"ip": "::", "port": 9443}, {"ip": "::1", "port": 8443}]}}`,
			[]int{8443, 9443},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewConfig(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.ListenPorts(); !slices.Equal(got, tc.want) {
				t.Errorf("ListenPorts() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRenderForcesNodeKeys(t *testing.T) {
	const apiPort, metricsPort = 12345, 23456
	users := map[string]*runtimeUser{"alice": {Username: "alice", Secret: testSecret}}

	fromPanel, err := NewConfig(`{"general": {"disable_colors": false, "telemetry": {"user_enabled": false, "core_enabled": false}}, "server": {"port": 2222}}`)
	if err != nil {
		t.Fatal(err)
	}
	minimal, err := NewConfig(`{"server": {"port": 2222}}`)
	if err != nil {
		t.Fatal(err)
	}
	logToFile, err := NewConfig(`{"logging": {"destination": "file", "path": "/tmp/x"}, "server": {"port": 2222}}`)
	if err != nil {
		t.Fatal(err)
	}
	// NewConfig rejects server.api; Render must still force it if a base
	// carries it some other way.
	direct := &Config{InboundTag: defaultInboundTag, base: map[string]any{
		"server": map[string]any{"api": map[string]any{"read_only": true, "enabled": false}},
	}}

	for name, cfg := range map[string]*Config{"panel overrides": fromPanel, "minimal": minimal, "log to file": logToFile, "direct base": direct} {
		t.Run(name, func(t *testing.T) {
			out, err := cfg.Render(users, nil, apiPort, metricsPort, "Bearer testtoken")
			if err != nil {
				t.Fatal(err)
			}
			tree := decodeTOML(t, out)
			expect := map[string]any{
				"general.disable_colors":         true,
				"general.telemetry.user_enabled": true,
				"logging.destination":            "stderr",
				"server.api.enabled":             true,
				"server.api.read_only":           false,
				"server.api.listen":              "127.0.0.1:" + strconv.Itoa(apiPort),
				"server.api.auth_header":         "Bearer testtoken",
				"server.metrics_port":            int64(metricsPort),
				"server.metrics_listen":          "127.0.0.1:" + strconv.Itoa(metricsPort),
				"access.users.alice":             testSecret,
			}
			for path, want := range expect {
				if got := tomlAt(tree, strings.Split(path, ".")...); got != want {
					t.Errorf("%s = %#v, want %#v\n---\n%s", path, got, want, out)
				}
			}
		})
	}

	// Render must not mutate the stored base.
	if telemetry := fromPanel.base["general"].(map[string]any)["telemetry"].(map[string]any); telemetry["user_enabled"] != false {
		t.Errorf("Render mutated the base config: telemetry = %v", telemetry)
	}
}

func TestRenderRejectsPortConflict(t *testing.T) {
	const apiPort, metricsPort = 12345, 23456
	users := map[string]*runtimeUser{"alice": {Username: "alice", Secret: testSecret}}

	cases := map[string]string{
		"server port is api port":       `{"server": {"port": 12345}}`,
		"server port is metrics port":   `{"server": {"port": 23456}}`,
		"listener port is api port":     `{"server": {"port": 443, "listeners": [{"ip": "::", "port": 12345}]}}`,
		"listener port is metrics port": `{"server": {"port": 443, "listeners": [{"ip": "0.0.0.0", "port": 23456}]}}`,
		"listener inherits server port": `{"server": {"port": 23456, "listeners": [{"ip": "0.0.0.0"}]}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := NewConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			_, err = cfg.Render(users, nil, apiPort, metricsPort, "Bearer x")
			if err == nil {
				t.Fatalf("Render succeeded for %s, want a port conflict error", raw)
			}
			if !strings.Contains(err.Error(), "conflicts") {
				t.Errorf("error %q does not describe a port conflict", err)
			}
		})
	}

	cfg, err := NewConfig(`{"server": {"port": 443, "listeners": [{"ip": "::", "port": 8443}]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Render(users, nil, apiPort, metricsPort, "Bearer x"); err != nil {
		t.Errorf("Render without a conflict failed: %v", err)
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
	tree := decodeTOML(t, out)
	for path, want := range map[string]any{
		"server.api.enabled":     true,
		"server.api.listen":      "127.0.0.1:12345",
		"server.api.auth_header": "Bearer testtoken",
		"server.metrics_port":    int64(23456),
		"server.metrics_listen":  "127.0.0.1:23456",
		"access.users.alice":     testSecret,
		"censorship.tls_domain":  "example.com",
	} {
		if got := tomlAt(tree, strings.Split(path, ".")...); got != want {
			t.Errorf("%s = %#v, want %#v\n---\n%s", path, got, want, out)
		}
	}
	if tomlAt(tree, "access", "user_enabled") != nil {
		t.Errorf("real users must not disable anyone via access.user_enabled")
	}

	// empty users + marker keeps telemt happy (telemt rejects empty [access.users])
	marker := &runtimeUser{Username: "pgm_0123456789abcdef", Secret: testSecret}
	out, err = cfg.Render(map[string]*runtimeUser{}, marker, 1, 2, "")
	if err != nil {
		t.Fatalf("render with marker failed: %v", err)
	}
	tree = decodeTOML(t, out)
	if tomlAt(tree, "access", "users", "pgm_0123456789abcdef") != testSecret {
		t.Errorf("marker user missing from rendered config")
	}
	if tomlAt(tree, "access", "user_enabled", "pgm_0123456789abcdef") != false {
		t.Errorf("marker must be rendered disabled, got:\n%s", out)
	}

	// empty users + no marker -> error (would crash telemt)
	if _, err := cfg.Render(map[string]*runtimeUser{}, nil, 1, 2, ""); err == nil {
		t.Errorf("expected error rendering with zero users and no marker")
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

	// include would render as a telemt file include -> error
	if _, _, err := activeUserFromCommon(mtUser("include", "mtproto", testSecret), "mtproto"); err == nil {
		t.Errorf("expected error for the username include")
	}
}

func TestActiveUsersSkipsInvalidUsers(t *testing.T) {
	users := []*common.User{
		mtUser("1", "mtproto", testSecret),
		{Email: "2", Inbounds: []string{"mtproto"}, Proxies: &common.Proxy{}},
		mtUser("3", "mtproto", testSecret[:31]),
		// Not tagged: neither returned nor skipped, even though it is invalid.
		{Email: "4", Inbounds: []string{"vless"}, Proxies: &common.Proxy{}},
		nil,
	}

	active, skipped := ActiveUsersFromCommon(users, "mtproto")
	if len(active) != 1 || active["1"] == nil {
		t.Errorf("active = %v, want only user 1", active)
	}
	if !slices.Equal(skipped, []string{"2", "3"}) {
		t.Errorf("skipped = %v, want [2 3]", skipped)
	}

	// An email repeated in one call is reported once.
	_, skipped = ActiveUsersFromCommon([]*common.User{
		mtUser("5", "mtproto", "bad"),
		mtUser("5", "mtproto", "bad"),
	}, "mtproto")
	if !slices.Equal(skipped, []string{"5"}) {
		t.Errorf("skipped = %v, want [5]", skipped)
	}
}

func TestBuildNextDesiredSkipsInvalidUsers(t *testing.T) {
	m := &MTProto{
		config: &Config{InboundTag: "mtproto"},
		desired: map[string]*runtimeUser{
			"1": {Username: "1", Secret: testSecret},
			"2": {Username: "2", Secret: testSecret},
		},
	}
	newSecret := "ffeeddccbbaa99887766554433221100"

	next := m.buildNextDesiredLocked([]*common.User{
		mtUser("2", "mtproto", "not-hex"), // invalid: treated as not included
		mtUser("3", "mtproto", newSecret), // valid: added
		nil,
	})

	if next["1"] == nil {
		t.Errorf("untouched user 1 was dropped: %v", next)
	}
	if _, ok := next["2"]; ok {
		t.Errorf("invalid user 2 must be removed from the desired set: %v", next)
	}
	if next["3"] == nil || next["3"].Secret != newSecret {
		t.Errorf("valid user 3 was not applied: %v", next)
	}
	if _, ok := m.desired["3"]; ok {
		t.Errorf("buildNextDesiredLocked must not mutate m.desired")
	}
}

func TestSyncUserReturnsValidationError(t *testing.T) {
	m := &MTProto{config: &Config{InboundTag: "mtproto"}}
	err := m.SyncUser(context.Background(), mtUser("1", "mtproto", testSecret[:31]))
	if err == nil || !strings.Contains(err.Error(), "invalid secret") {
		t.Errorf("SyncUser error = %v, want the secret validation error", err)
	}
}

const webTestListeners = `"listeners": [{"ip": "0.0.0.0"}, {"ip": "127.0.0.1", "port": 18080, "transport": "web", "web_trusted_proxy_cidrs": ["127.0.0.1/32"]}]`

// webTestConfig builds a WEB config with one vhost; vhostExtra is appended to
// the vhost object.
func webTestConfig(vhostExtra string) string {
	return `{"server": {"port": 443, ` + webTestListeners + `}, "web": {"enabled": true, "vhosts": [{"host": "proxy.example.com", "public_addr": "203.0.113.10:443", "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:18081"}` + vhostExtra + `}]}}`
}

func TestNewConfigAcceptsWeb(t *testing.T) {
	cfg, err := NewConfig(webTestConfig(`, "user_profile": {"secret_mode": "plain", "max_sessions": 8}`))
	if err != nil {
		t.Fatalf("NewConfig failed: %v", err)
	}
	if !cfg.HasWeb() {
		t.Errorf("HasWeb() = false, want true")
	}
	want := []webUserProfile{{SecretMode: "plain", MaxSessions: 8}}
	if !slices.Equal(cfg.webProfiles, want) {
		t.Errorf("webProfiles = %+v, want %+v", cfg.webProfiles, want)
	}
	vhost := cfg.base["web"].(map[string]any)["vhosts"].([]any)[0].(map[string]any)
	if _, ok := vhost["user_profile"]; ok {
		t.Errorf("user_profile must be stripped from the stored vhost: %v", vhost)
	}

	cfg, err = NewConfig(webTestConfig(""))
	if err != nil {
		t.Fatalf("NewConfig without user_profile failed: %v", err)
	}
	want = []webUserProfile{{SecretMode: "dd"}}
	if !slices.Equal(cfg.webProfiles, want) {
		t.Errorf("default webProfiles = %+v, want %+v", cfg.webProfiles, want)
	}

	cfg, err = NewConfig(`{"server": {"port": 443}}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HasWeb() || cfg.webProfiles != nil {
		t.Errorf("a config without web must not report WEB: HasWeb=%v profiles=%v", cfg.HasWeb(), cfg.webProfiles)
	}
}

func TestNewConfigRejectsUnsafeWeb(t *testing.T) {
	withListener := func(listener string) string {
		return `{"server": {"port": 443, "listeners": [{"ip": "0.0.0.0"}, ` + listener + `]}, "web": {"enabled": true, "vhosts": [{"host": "proxy.example.com", "public_addr": "203.0.113.10:443", "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:18081"}}]}}`
	}
	withVhost := func(vhost string) string {
		return `{"server": {"port": 443, ` + webTestListeners + `}, "web": {"enabled": true, "vhosts": [` + vhost + `]}}`
	}
	withWeb := func(web string) string {
		return `{"server": {"port": 443, ` + webTestListeners + `}, "web": ` + web + `}`
	}
	const host = `"host": "proxy.example.com", "public_addr": "203.0.113.10:443"`

	cases := []struct {
		name, raw, want string
	}{
		{"listener ip any v4", withListener(`{"ip": "0.0.0.0", "port": 18080, "transport": "web"}`), "private"},
		{"listener ip any v6", withListener(`{"ip": "::", "port": 18080, "transport": "web"}`), "private"},
		{"listener ip public", withListener(`{"ip": "198.51.100.1", "port": 18080, "transport": "web"}`), "private"},
		{"listener ip missing", withListener(`{"port": 18080, "transport": "web"}`), "private"},
		{"listener without port", withListener(`{"ip": "127.0.0.1", "transport": "web"}`), "port"},
		{"static directory decoy", withVhost(`{` + host + `, "decoy": {"mode": "static_directory", "directory": "/srv"}}`), "static_directory"},
		{"decoy hostname", withVhost(`{` + host + `, "decoy": {"mode": "http_upstream", "upstream": "http://example.com"}}`), "private"},
		{"decoy public ip", withVhost(`{` + host + `, "decoy": {"mode": "http_upstream", "upstream": "http://8.8.8.8"}}`), "private"},
		{"decoy missing", withVhost(`{` + host + `}`), "decoy"},
		{"vhost profiles", withVhost(`{` + host + `, "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:1"}, "profiles": []}`), "must not define web.vhosts[0].profiles"},
		{"web debug", withWeb(`{"enabled": true, "debug": {}, "vhosts": [{` + host + `, "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:1"}}]}`), "must not define web.debug"},
		{"web max_profiles", withWeb(`{"enabled": true, "limits": {"max_profiles": 9}, "vhosts": [{` + host + `, "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:1"}}]}`), "must not define web.limits.max_profiles"},
		{"secret mode ee", webTestConfig(`, "user_profile": {"secret_mode": "ee"}`), "secret_mode"},
		{"negative limit", webTestConfig(`, "user_profile": {"max_sessions": -1}`), "max_sessions"},
		{"fraction limit", webTestConfig(`, "user_profile": {"max_streams": 1.5}`), "max_streams"},
		{"string limit", webTestConfig(`, "user_profile": {"max_streams_per_session": "4"}`), "max_streams_per_session"},
		{"enabled without listener", `{"server": {"port": 443}, "web": {"enabled": true, "vhosts": [{` + host + `, "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:1"}}]}}`, "web"},
		{"listener without enabled web", withWeb(`{"enabled": false, "vhosts": [{` + host + `, "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:1"}}]}`), "web"},
		{"listener without vhost", withWeb(`{"enabled": true, "vhosts": []}`), "web"},
		{"listener without web", `{"server": {"port": 443, ` + webTestListeners + `}}`, "web"},
		{"socks listener", `{"server": {"listeners": [{"ip": "::", "transport": "socks"}]}}`, "must be \"mtproxy\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewConfig(tc.raw)
			if err == nil {
				t.Fatalf("NewConfig(%s) succeeded, want an error containing %q", tc.raw, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestWebListenerPortClash(t *testing.T) {
	const web = `"web": {"enabled": true, "vhosts": [{"host": "proxy.example.com", "public_addr": "203.0.113.10:443", "decoy": {"mode": "http_upstream", "upstream": "http://127.0.0.1:18081"}}]}`
	cases := map[string]string{
		"server port":          `{"server": {"port": 443, "listeners": [{"ip": "127.0.0.1", "port": 443, "transport": "web"}]}, ` + web + `}`,
		"native listener port": `{"server": {"port": 443, "listeners": [{"ip": "0.0.0.0", "port": 8443}, {"ip": "10.0.0.5", "port": 8443, "transport": "web"}]}, ` + web + `}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewConfig(raw)
			if err == nil {
				t.Fatalf("NewConfig(%s) succeeded, want a port clash error", raw)
			}
			if !strings.Contains(err.Error(), "port") {
				t.Errorf("error %q does not mention the port", err)
			}
		})
	}
}

// webProfilesAt returns web.vhosts[index].profiles of a decoded render.
func webProfilesAt(t *testing.T, tree map[string]any, index int) []any {
	t.Helper()
	vhosts, ok := tomlAt(tree, "web", "vhosts").([]any)
	if !ok || len(vhosts) <= index {
		t.Fatalf("web.vhosts = %#v, want at least %d entries", tomlAt(tree, "web", "vhosts"), index+1)
	}
	vhost, _ := vhosts[index].(map[string]any)
	profiles, _ := vhost["profiles"].([]any)
	return profiles
}

func TestRenderWebProfiles(t *testing.T) {
	cfg, err := NewConfig(webTestConfig(`, "user_profile": {"secret_mode": "plain", "max_sessions": 8}`))
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]*runtimeUser{
		"2": {Username: "2", Secret: otherSecret},
		"1": {Username: "1", Secret: testSecret},
	}
	marker := &runtimeUser{Username: "pgm_0123456789abcdef", Secret: thirdSecret}
	out, err := cfg.Render(users, marker, 12345, 23456, "Bearer token")
	if err != nil {
		t.Fatal(err)
	}
	tree := decodeTOML(t, out)

	profiles := webProfilesAt(t, tree, 0)
	want := []map[string]any{
		{"user": "1", "secret_mode": "plain", "max_sessions": int64(8)},
		{"user": "2", "secret_mode": "plain", "max_sessions": int64(8)},
	}
	if len(profiles) != len(want) {
		t.Fatalf("profiles = %#v, want %#v\n---\n%s", profiles, want, out)
	}
	for index, raw := range profiles {
		profile, _ := raw.(map[string]any)
		if !mapsEqual(profile, want[index]) {
			t.Errorf("profiles[%d] = %#v, want %#v", index, profile, want[index])
		}
	}
	if got := tomlAt(tree, "web", "limits", "max_profiles"); got != int64(262144) {
		t.Errorf("web.limits.max_profiles = %#v, want 262144", got)
	}
	if _, ok := tomlAt(tree, "web", "vhosts").([]any)[0].(map[string]any)["user_profile"]; ok {
		t.Errorf("user_profile must not reach telemt\n---\n%s", out)
	}
}

func mapsEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if other, ok := b[key]; !ok || other != value {
			return false
		}
	}
	return true
}

func TestRenderWebMarkerProfileOnlyWithoutUsers(t *testing.T) {
	cfg, err := NewConfig(webTestConfig(""))
	if err != nil {
		t.Fatal(err)
	}
	marker := &runtimeUser{Username: "pgm_0123456789abcdef", Secret: thirdSecret}

	// telemt rejects an enabled vhost without profiles, so the marker fills in
	// while the node has no users.
	out, err := cfg.Render(nil, marker, 12345, 23456, "Bearer token")
	if err != nil {
		t.Fatal(err)
	}
	profiles := webProfilesAt(t, decodeTOML(t, out), 0)
	wantMarker := map[string]any{"user": marker.Username, "secret_mode": "dd"}
	if len(profiles) != 1 || !mapsEqual(profiles[0].(map[string]any), wantMarker) {
		t.Errorf("profiles without users = %#v, want only %#v", profiles, wantMarker)
	}

	out, err = cfg.Render(map[string]*runtimeUser{"1": {Username: "1", Secret: testSecret}}, marker, 12345, 23456, "Bearer token")
	if err != nil {
		t.Fatal(err)
	}
	profiles = webProfilesAt(t, decodeTOML(t, out), 0)
	wantUser := map[string]any{"user": "1", "secret_mode": "dd"}
	if len(profiles) != 1 || !mapsEqual(profiles[0].(map[string]any), wantUser) {
		t.Errorf("profiles with one user = %#v, want only %#v", profiles, wantUser)
	}
}

// TestRenderWebConfigSize checks that 50,000 users with one WEB vhost stay
// under telemt's 8 MiB config limit. Users carry a secret only and the vhost
// sets one profile limit, the common case; the logged bytes per user give the
// largest user count that fits.
func TestRenderWebConfigSize(t *testing.T) {
	const userCount = 50000
	const sizeLimit = 8388608
	cfg, err := NewConfig(webTestConfig(`, "user_profile": {"secret_mode": "plain", "max_sessions": 8}`))
	if err != nil {
		t.Fatal(err)
	}
	users := make(map[string]*runtimeUser, userCount)
	for id := 1; id <= userCount; id++ {
		username := strconv.Itoa(id)
		users[username] = &runtimeUser{Username: username, Secret: testSecret}
	}
	marker := &runtimeUser{Username: "pgm_0123456789abcdef", Secret: thirdSecret}

	out, err := cfg.Render(users, marker, 12345, 23456, "Bearer token")
	if err != nil {
		t.Fatal(err)
	}
	empty, err := cfg.Render(nil, marker, 12345, 23456, "Bearer token")
	if err != nil {
		t.Fatal(err)
	}
	perUser := float64(len(out)-len(empty)) / userCount
	t.Logf("%d users: %d bytes, %.1f bytes per user, about %d users fit in %d bytes", userCount, len(out), perUser, int(float64(sizeLimit-len(empty))/perUser), sizeLimit)
	if len(out) >= sizeLimit {
		t.Errorf("rendered config is %d bytes, want under %d", len(out), sizeLimit)
	}
	// Decoding a file this large takes seconds, so count the tables instead.
	if got := strings.Count(out, "[[web.vhosts.profiles]]"); got != userCount {
		t.Errorf("rendered %d profiles, want %d", got, userCount)
	}
}
