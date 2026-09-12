package config

import "testing"

const validTestAPIKey = "123e4567-e89b-12d3-a456-426614174000"

func TestLoadRejectsMissingOrUnsafeAPIKey(t *testing.T) {
	for _, apiKey := range []string{"", "not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		t.Run(apiKey, func(t *testing.T) {
			t.Setenv("API_KEY", apiKey)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted unsafe API_KEY %q", apiKey)
			}
		})
	}
}

func TestLoadRejectsNonPositiveStatsIntervals(t *testing.T) {
	t.Setenv("API_KEY", validTestAPIKey)
	for _, interval := range []string{"0", "-1"} {
		t.Run(interval, func(t *testing.T) {
			t.Setenv("STATS_UPDATE_INTERVAL_SECONDS", interval)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted STATS_UPDATE_INTERVAL_SECONDS=%s", interval)
			}
		})
	}
}

func TestLoadAcceptsValidAPIKeyAndIntervals(t *testing.T) {
	t.Setenv("API_KEY", validTestAPIKey)
	t.Setenv("STATS_UPDATE_INTERVAL_SECONDS", "10")
	t.Setenv("STATS_CLEANUP_INTERVAL_SECONDS", "300")
	if _, err := Load(); err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
}
