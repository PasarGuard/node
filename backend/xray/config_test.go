package xray

import (
	"slices"
	"testing"
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
