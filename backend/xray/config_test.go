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
