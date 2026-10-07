package config

import "testing"

func TestLoadRejectsMissingOrInvalidAPIKey(t *testing.T) {
	cases := map[string]string{
		"missing":    "",
		"not a uuid": "not-a-uuid",
		"all zero":   "00000000-0000-0000-0000-000000000000",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("API_KEY", value)

			if _, err := Load(); err == nil {
				t.Fatalf("expected Load to fail for API_KEY=%q", value)
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
