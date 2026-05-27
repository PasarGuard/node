package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func TestShouldIncludeObservatoryOutbound(t *testing.T) {
	protocolByTag := map[string]string{
		"blocked":  "blackhole",
		"dns-out":  "dns",
		"loop-out": "loopback",
		"direct":   "freedom",
	}

	cases := []struct {
		tag  string
		want bool
	}{
		{tag: "blocked", want: false},
		{tag: "dns-out", want: false},
		{tag: "loop-out", want: false},
		{tag: "direct", want: true},
		{tag: "unknown", want: true},
	}

	for _, tc := range cases {
		if got := shouldIncludeObservatoryOutbound(protocolByTag, tc.tag); got != tc.want {
			t.Fatalf("tag %q: got %v want %v", tc.tag, got, tc.want)
		}
	}
}

func TestApplyAPISanitizesObservatorySelectors(t *testing.T) {
	cfg := &Config{
		OutboundConfigs: []any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "blocked", "protocol": "blackhole"},
			map[string]any{"tag": "dns-out", "protocol": "dns"},
			map[string]any{"tag": "loop-out", "protocol": "loopback"},
		},
		Observatory: map[string]any{
			"subjectSelector": []any{"direct", "blocked", "dns-out", "loop-out"},
		},
		BurstObservatory: map[string]any{
			"subjectSelector": []any{"blocked", "direct"},
		},
	}

	if err := cfg.ApplyAPI(10001, 10002); err != nil {
		t.Fatal(err)
	}

	obs := cfg.Observatory["subjectSelector"].([]any)
	if len(obs) != 1 || obs[0] != "direct" {
		t.Fatalf("unexpected observatory selectors: %#v", obs)
	}

	burst := cfg.BurstObservatory["subjectSelector"].([]any)
	if len(burst) != 1 || burst[0] != "direct" {
		t.Fatalf("unexpected burst observatory selectors: %#v", burst)
	}
}

func TestApplyAPIAddsMalformedDomainGuardWhenBlackholeExists(t *testing.T) {
	cfg := &Config{
		InboundConfigs: []*Inbound{},
		OutboundConfigs: []any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "Block", "protocol": "blackhole"},
		},
	}

	if err := cfg.ApplyAPI(10001, 10002); err != nil {
		t.Fatal(err)
	}

	if len(cfg.RouterConfig.RuleList) < 2 {
		t.Fatalf("expected API and malformed-domain guard rules, got %d", len(cfg.RouterConfig.RuleList))
	}

	rule := string(cfg.RouterConfig.RuleList[1])
	if !containsAll(rule, malformedDomainGuardRuleTag, `"outboundTag":"Block"`, `regexp:^.{254,}$`) {
		t.Fatalf("unexpected malformed-domain guard rule: %s", rule)
	}
}

func TestApplyAPIRemovesExistingMalformedDomainGuard(t *testing.T) {
	cfg := &Config{
		InboundConfigs: []*Inbound{},
		OutboundConfigs: []any{
			map[string]any{"tag": "Block", "protocol": "blackhole"},
		},
		RouterConfig: &conf.RouterConfig{
			RuleList: []json.RawMessage{
				json.RawMessage(`{"type":"field","ruleTag":"PG_NODE_MALFORMED_DOMAIN_GUARD","outboundTag":"old","domain":["regexp:^.{254,}$"]}`),
			},
		},
	}

	if err := cfg.ApplyAPI(10001, 10002); err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, raw := range cfg.RouterConfig.RuleList {
		if strings.Contains(string(raw), malformedDomainGuardRuleTag) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected one malformed-domain guard rule, got %d", count)
	}
}

func containsAll(s string, values ...string) bool {
	for _, value := range values {
		if !strings.Contains(s, value) {
			return false
		}
	}
	return true
}
