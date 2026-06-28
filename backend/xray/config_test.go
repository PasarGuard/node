package xray

import (
	"slices"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func TestSanitizeAPIServices(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "nil yields required only",
			in:   nil,
			want: []string{"HandlerService", "LoggerService", "StatsService"},
		},
		{
			name: "empty yields required only",
			in:   []string{},
			want: []string{"HandlerService", "LoggerService", "StatsService"},
		},
		{
			name: "routing service appended",
			in:   []string{"routingservice"},
			want: []string{"HandlerService", "LoggerService", "StatsService", "RoutingService"},
		},
		{
			name: "dedupe and case fold",
			in:   []string{"HandlerService", "handlerservice", "ROUTINGSERVICE"},
			want: []string{"HandlerService", "LoggerService", "StatsService", "RoutingService"},
		},
		{
			name: "dedupe extras across case",
			in:   []string{"routingservice", "RoutingService"},
			want: []string{"HandlerService", "LoggerService", "StatsService", "RoutingService"},
		},
		{
			name: "unknown dropped, required preserved",
			in:   []string{"foo", "RoutigService"},
			want: []string{"HandlerService", "LoggerService", "StatsService"},
		},
		{
			name: "extras sorted deterministically",
			in:   []string{"routingservice", "observatoryservice", "reflectionservice"},
			want: []string{"HandlerService", "LoggerService", "StatsService", "ObservatoryService", "ReflectionService", "RoutingService"},
		},
		{
			name: "whitespace trimmed",
			in:   []string{"  routingservice  "},
			want: []string{"HandlerService", "LoggerService", "StatsService", "RoutingService"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeAPIServices(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("sanitizeAPIServices(%#v) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

func TestApplyAPIMergesUserServices(t *testing.T) {
	cfg := &Config{
		InboundConfigs: []*Inbound{},
		API: &conf.APIConfig{
			Services: []string{"RoutingService"},
			Tag:      "custom",
			Listen:   "1.2.3.4:5",
		},
	}

	if err := cfg.ApplyAPI(10001, 10002); err != nil {
		t.Fatal(err)
	}

	want := []string{"HandlerService", "LoggerService", "StatsService", "RoutingService"}
	if !slices.Equal(cfg.API.Services, want) {
		t.Fatalf("API.Services = %#v, want %#v", cfg.API.Services, want)
	}
	if cfg.API.Tag != "API" {
		t.Fatalf("API.Tag = %q, want %q", cfg.API.Tag, "API")
	}
	if cfg.API.Listen != "" {
		t.Fatalf("API.Listen = %q, want empty (node forces loopback API_INBOUND only)", cfg.API.Listen)
	}
}

func TestApplyAPINilAPIYieldsRequiredServices(t *testing.T) {
	cfg := &Config{InboundConfigs: []*Inbound{}}

	if err := cfg.ApplyAPI(10001, 10002); err != nil {
		t.Fatal(err)
	}

	want := []string{"HandlerService", "LoggerService", "StatsService"}
	if !slices.Equal(cfg.API.Services, want) {
		t.Fatalf("API.Services = %#v, want %#v", cfg.API.Services, want)
	}
}

func observatorySelector(t *testing.T, cfg *Config) ([]string, bool) {
	t.Helper()
	if cfg.Observatory == nil {
		return nil, false
	}
	raw, ok := cfg.Observatory["subjectSelector"]
	if !ok {
		return []string{}, true
	}
	sel, ok := raw.([]string)
	if !ok {
		t.Fatalf("subjectSelector type = %T, want []string", raw)
	}
	return sel, true
}

func TestApplyAPIInjectsObservatoryWhenServiceEnabled(t *testing.T) {
	cfg := &Config{
		InboundConfigs: []*Inbound{},
		API:            &conf.APIConfig{Services: []string{"ObservatoryService"}},
		OutboundConfigs: []any{
			map[string]any{"tag": "proxy", "protocol": "vless"},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
	}

	if err := cfg.ApplyAPI(10001, 10002); err != nil {
		t.Fatal(err)
	}

	sel, ok := observatorySelector(t, cfg)
	if !ok {
		t.Fatal("expected observatory injected, got nil")
	}
	if !slices.Equal(sel, []string{"proxy"}) {
		t.Fatalf("subjectSelector = %#v, want [proxy] (blackhole excluded)", sel)
	}
	if cfg.Observatory["probeURL"] != defaultObservatoryProbeURL {
		t.Fatalf("probeURL = %v, want %q", cfg.Observatory["probeURL"], defaultObservatoryProbeURL)
	}
	if cfg.Observatory["probeInterval"] != defaultObservatoryProbeInterval {
		t.Fatalf("probeInterval = %v, want %q", cfg.Observatory["probeInterval"], defaultObservatoryProbeInterval)
	}
}

func TestApplyAPINoObservatoryWhenServiceDisabled(t *testing.T) {
	cfg := &Config{
		InboundConfigs:  []*Inbound{},
		API:             &conf.APIConfig{Services: []string{"RoutingService"}},
		OutboundConfigs: []any{map[string]any{"tag": "proxy", "protocol": "vless"}},
	}

	if err := cfg.ApplyAPI(10001, 10002); err != nil {
		t.Fatal(err)
	}
	if cfg.Observatory != nil {
		t.Fatalf("observatory = %#v, want nil (ObservatoryService not enabled)", cfg.Observatory)
	}
}

func TestApplyAPIRespectsUserObservatory(t *testing.T) {
	cfg := &Config{
		InboundConfigs:  []*Inbound{},
		API:             &conf.APIConfig{Services: []string{"ObservatoryService"}},
		OutboundConfigs: []any{map[string]any{"tag": "proxy", "protocol": "vless"}},
		Observatory:     map[string]any{"subjectSelector": []any{"proxy"}, "probeURL": "https://example.com"},
	}

	if err := cfg.ApplyAPI(10001, 10002); err != nil {
		t.Fatal(err)
	}
	if cfg.Observatory["probeURL"] != "https://example.com" {
		t.Fatalf("probeURL = %v, want user value preserved", cfg.Observatory["probeURL"])
	}
}

func TestApplyAPIRespectsUserBurstObservatory(t *testing.T) {
	cfg := &Config{
		InboundConfigs:   []*Inbound{},
		API:              &conf.APIConfig{Services: []string{"ObservatoryService"}},
		OutboundConfigs:  []any{map[string]any{"tag": "proxy", "protocol": "vless"}},
		BurstObservatory: map[string]any{"subjectSelector": []any{"proxy"}},
	}

	if err := cfg.ApplyAPI(10001, 10002); err != nil {
		t.Fatal(err)
	}
	if cfg.Observatory != nil {
		t.Fatalf("observatory = %#v, want nil (burstObservatory satisfies the dependency)", cfg.Observatory)
	}
}

func TestApplyAPIInjectsObservatoryWithNoEligibleOutbounds(t *testing.T) {
	cfg := &Config{
		InboundConfigs:  []*Inbound{},
		API:             &conf.APIConfig{Services: []string{"ObservatoryService"}},
		OutboundConfigs: []any{map[string]any{"tag": "block", "protocol": "blackhole"}},
	}

	if err := cfg.ApplyAPI(10001, 10002); err != nil {
		t.Fatal(err)
	}
	sel, ok := observatorySelector(t, cfg)
	if !ok {
		t.Fatal("expected observatory injected even with no eligible outbounds")
	}
	if len(sel) != 0 {
		t.Fatalf("subjectSelector = %#v, want empty", sel)
	}
}
