package xray

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

const (
	planDirect = `{"tag": "direct", "protocol": "freedom"}`
	planBlock  = `{"tag": "block", "protocol": "blackhole"}`
	planRule   = `{"type": "field", "domain": ["example.com"], "outboundTag": "block"}`
)

func livePlanJSON(outbounds, rules string) string {
	return fmt.Sprintf(`{
		"inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": 20000, "protocol": "vless", "settings": {"clients": [], "decryption": "none"}}],
		"outbounds": %s,
		"routing": {"domainStrategy": "AsIs", "rules": %s}
	}`, outbounds, rules)
}

// livePlanConfig builds a config the way the node does before starting xray.
func livePlanConfig(t *testing.T, raw string, exclude []string) *Config {
	t.Helper()
	cfg, err := NewConfig(raw, exclude)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.ApplyAPI(10085, 10086); err != nil {
		t.Fatal(err)
	}
	cfg.GetLogFiles()
	return cfg
}

func planOutbounds(items ...string) string {
	return "[" + strings.Join(items, ", ") + "]"
}

func planAdd(tag string) liveStep    { return liveStep{kind: liveAddOutbound, tag: tag} }
func planRemove(tag string) liveStep { return liveStep{kind: liveRemoveOutbound, tag: tag} }
func planRouting() liveStep          { return liveStep{kind: liveReplaceRouting} }

func TestPlanLiveUpdate(t *testing.T) {
	cur := livePlanConfig(t, livePlanJSON(planOutbounds(planDirect, planBlock), "["+planRule+"]"), nil)

	cases := []struct {
		name string
		next string
		want []liveStep
	}{
		{
			name: "nothing changed",
			next: livePlanJSON(planOutbounds(planDirect, planBlock), "["+planRule+"]"),
		},
		{
			name: "rule changed",
			next: livePlanJSON(planOutbounds(planDirect, planBlock), `[{"type": "field", "domain": ["example.org"], "outboundTag": "block"}]`),
			want: []liveStep{planRouting()},
		},
		{
			name: "outbound added with a rule",
			next: livePlanJSON(
				planOutbounds(planDirect, planBlock, `{"tag": "proxy", "protocol": "socks", "settings": {"address": "10.0.0.2", "port": 1080}}`),
				"["+planRule+`, {"type": "field", "domain": ["example.org"], "outboundTag": "proxy"}]`,
			),
			want: []liveStep{planAdd("proxy"), planRouting()},
		},
		{
			name: "outbound edited",
			next: livePlanJSON(planOutbounds(planDirect, `{"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}}`), "["+planRule+"]"),
			want: []liveStep{planRemove("block"), planAdd("block")},
		},
		{
			// The blackhole outbound also carries the node's malformed-domain guard
			// rule, so the routing changes before the outbound goes.
			name: "outbound deleted with its rule",
			next: livePlanJSON(planOutbounds(planDirect), "[]"),
			want: []liveStep{planRouting(), planRemove("block")},
		},
		{
			name: "default edited",
			next: livePlanJSON(planOutbounds(`{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}`, planBlock), "["+planRule+"]"),
			want: []liveStep{planRemove("direct"), planAdd("direct")},
		},
		{
			name: "default moved",
			next: livePlanJSON(planOutbounds(planBlock, planDirect), "["+planRule+"]"),
			want: []liveStep{planRemove("direct"), planRemove("block"), planAdd("block"), planAdd("direct")},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			steps, reason := planLiveUpdate(cur, livePlanConfig(t, tc.next, nil))
			if reason != "" {
				t.Fatalf("planLiveUpdate wants a restart: %s", reason)
			}
			if !slices.Equal(steps, tc.want) {
				t.Fatalf("steps = %v, want %v", steps, tc.want)
			}
		})
	}
}

func TestPlanLiveUpdateNeedsRestart(t *testing.T) {
	base := livePlanJSON(planOutbounds(planDirect, planBlock), "["+planRule+"]")
	cur := livePlanConfig(t, base, nil)

	cases := []struct {
		name    string
		next    string
		exclude []string
	}{
		{name: "inbound changed", next: strings.Replace(base, "20000", "20001", 1)},
		{name: "inbound excluded", next: base, exclude: []string{"in"}},
		{name: "domainStrategy changed", next: strings.Replace(base, `"AsIs"`, `"IPIfNonMatch"`, 1)},
		{name: "dns added", next: strings.Replace(base, `"inbounds"`, `"dns": {"servers": ["1.1.1.1"]}, "inbounds"`, 1)},
		{name: "outbound without tag", next: livePlanJSON(planOutbounds(planDirect, planBlock, `{"protocol": "freedom"}`), "["+planRule+"]")},
		{name: "outbound tag used twice", next: livePlanJSON(planOutbounds(planDirect, planBlock, `{"tag": "block", "protocol": "freedom"}`), "["+planRule+"]")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			steps, reason := planLiveUpdate(cur, livePlanConfig(t, tc.next, tc.exclude))
			if reason == "" {
				t.Fatalf("planned %v, want a restart", steps)
			}
		})
	}
}

func TestPlanLiveUpdateOutboundsThatKeepRunning(t *testing.T) {
	const id = "b831381d-6324-4d53-ad4f-8cda48b30811"
	warp := `{"tag": "warp", "protocol": "wireguard", "settings": {"secretKey": "x", "peers": [{"publicKey": "y", "endpoint": "162.159.192.1:2408"}]}}`
	reverse := `{"tag": "bridge", "protocol": "vless", "settings": {"vnext": [{"address": "10.0.0.3", "port": 443, "users": [{"id": "` + id + `", "encryption": "none", "reverse": {"tag": "r"}}]}]}}`
	testpre := `{"tag": "pre", "protocol": "vless", "settings": {"address": "10.0.0.4", "port": 443, "id": "` + id + `", "encryption": "none", "testpre": 2}}`
	plain := `{"tag": "plain", "protocol": "vless", "settings": {"address": "10.0.0.5", "port": 443, "id": "` + id + `", "encryption": "none"}}`
	future := `{"tag": "future", "protocol": "somethingnew"}`
	with := func(extra ...string) *Config {
		return livePlanConfig(t, livePlanJSON(planOutbounds(append([]string{planDirect, planBlock}, extra...)...), "["+planRule+"]"), nil)
	}

	if steps, reason := planLiveUpdate(with(), with(warp)); reason != "" || !slices.Equal(steps, []liveStep{planAdd("warp")}) {
		t.Fatalf("adding a wireguard outbound: steps %v, restart reason %q", steps, reason)
	}
	if steps, reason := planLiveUpdate(with(plain), with()); reason != "" || !slices.Equal(steps, []liveStep{planRemove("plain")}) {
		t.Fatalf("removing a plain vless outbound: steps %v, restart reason %q", steps, reason)
	}

	restarts := []struct {
		name      string
		cur, next *Config
	}{
		{"wireguard edited", with(warp), with(strings.Replace(warp, "2408", "500", 1))},
		{"wireguard removed", with(warp), with()},
		{"vless reverse removed", with(reverse), with()},
		{"vless testpre removed", with(testpre), with()},
		{"unknown protocol removed", with(future), with()},
	}
	for _, tc := range restarts {
		if steps, reason := planLiveUpdate(tc.cur, tc.next); reason == "" {
			t.Fatalf("%s: planned %v, want a restart", tc.name, steps)
		}
	}
}

func TestPlanLiveUpdateIgnoresExcludeOrder(t *testing.T) {
	raw := `{
		"inbounds": [
			{"tag": "a", "port": 20000, "protocol": "vless", "settings": {"clients": [], "decryption": "none"}},
			{"tag": "b", "port": 20001, "protocol": "vless", "settings": {"clients": [], "decryption": "none"}}
		],
		"outbounds": [` + planDirect + `]
	}`

	steps, reason := planLiveUpdate(livePlanConfig(t, raw, []string{"a", "b"}), livePlanConfig(t, raw, []string{"b", "a"}))
	if reason != "" || len(steps) != 0 {
		t.Fatalf("same excludes in another order: steps %v, restart reason %q", steps, reason)
	}
}
