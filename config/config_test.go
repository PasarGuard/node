package config

import (
	"os"
	"strings"
	"testing"
)

// unsetEnv removes name for the duration of the test (t.Setenv can only set, not unset).
func unsetEnv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "") // registers the restore of the original value
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unset %s: %v", name, err)
	}
}

func TestLoadRejectsMissingAPIKey(t *testing.T) {
	unsetEnv(t, "API_KEY")

	cfg, err := Load()
	if err == nil || !strings.Contains(err.Error(), "API_KEY is not set") {
		t.Fatalf("expected a not-set error, got %v", err)
	}
	if cfg == nil {
		t.Fatal("Load must still return the config (NewTestConfig relies on it)")
	}
}

func TestLoadRejectsInvalidAPIKey(t *testing.T) {
	cases := map[string]string{
		"empty":      "",
		"not a uuid": "not-a-uuid",
		"all zero":   "00000000-0000-0000-0000-000000000000",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("API_KEY", value)

			cfg, err := Load()
			if err == nil {
				t.Fatalf("expected Load to fail for API_KEY=%q", value)
			}
			if cfg == nil {
				t.Fatal("Load must still return the config (NewTestConfig relies on it)")
			}
		})
	}
}

func TestLoadAcceptsValidAPIKey(t *testing.T) {
	const key = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	t.Setenv("API_KEY", key)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.ApiKey.String() != key {
		t.Fatalf("expected ApiKey %s, got %s", key, cfg.ApiKey)
	}
}
