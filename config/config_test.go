package config

import (
	"bytes"
	"fmt"
	"log"
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

func TestLoadAcceptsNodeHostIPsAndLocalhost(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0":      "0.0.0.0",
		"10.0.0.5":     "10.0.0.5",
		"::":           "::",
		"::1":          "::1",
		"2001:db8::1":  "2001:db8::1",
		"fe80::1%eth0": "fe80::1%eth0",
		" 0.0.0.0 ":    "0.0.0.0",
		"localhost":    "127.0.0.1",
		" LocalHost ":  "127.0.0.1",
	}
	for value, want := range cases {
		t.Run(value, func(t *testing.T) {
			t.Setenv("API_KEY", "3fa85f64-5717-4562-b3fc-2c963f66afa6")
			t.Setenv("NODE_HOST", value)
			logs := captureLog(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load failed for NODE_HOST=%q: %v", value, err)
			}
			if cfg.NodeHost != want {
				t.Fatalf("expected NodeHost %q for NODE_HOST=%q, got %q", want, value, cfg.NodeHost)
			}
			if strings.Contains(logs.String(), "NODE_HOST") {
				t.Fatalf("did not expect a NODE_HOST log for %q, got %q", value, logs.String())
			}
		})
	}
}

func TestLoadDefaultsNodeHostToAllIPv4(t *testing.T) {
	t.Setenv("API_KEY", "3fa85f64-5717-4562-b3fc-2c963f66afa6")
	unsetEnv(t, "NODE_HOST")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.NodeHost != "0.0.0.0" {
		t.Fatalf("expected default NodeHost 0.0.0.0, got %q", cfg.NodeHost)
	}
}

// captureLog collects what the standard logger writes during the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &buf
}

// An invalid NODE_HOST keeps the old fallback to 127.0.0.1, so an upgrade never stops a node
// that used to start, but it is now logged as an error with the bad value.
func TestLoadFallsBackToLoopbackOnInvalidNodeHost(t *testing.T) {
	for _, value := range []string{"", "node.example.com", "256.1.1.1", "[::1]", "0.0.0.0:62050", "10.0.0.5%eth0", "fe80::1%"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("API_KEY", "3fa85f64-5717-4562-b3fc-2c963f66afa6")
			t.Setenv("NODE_HOST", value)
			logs := captureLog(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("an invalid NODE_HOST must not fail Load, got %v", err)
			}
			if cfg.NodeHost != "127.0.0.1" {
				t.Fatalf("expected the loopback fallback for NODE_HOST=%q, got %q", value, cfg.NodeHost)
			}
			if want := fmt.Sprintf("[Error] NODE_HOST %q", value); !strings.Contains(logs.String(), want) {
				t.Fatalf("expected an error log containing %s, got %q", want, logs.String())
			}
		})
	}
}
