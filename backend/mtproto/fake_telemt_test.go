//go:build !windows

package mtproto

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/netutil"
)

// fakeTelemtEnv names the file with the fakeTelemt options; the wrapper
// script sets it for the helper process.
const fakeTelemtEnv = "MTPROTO_FAKE_TELEMT_MODE"

// fakeTelemt describes how the stand-in telemt behaves. The test binary
// re-executes itself as TestHelperFakeTelemt (through a wrapper script that
// writeFakeTelemt puts in a temp dir), so the fake runs as a real child process
// the node starts, signals and reaps.
type fakeTelemt struct {
	Version string `json:"version"` // --version output, default 3.5.14
	// RecordFile receives the fake's argv, cwd and pid once its signal
	// handlers are installed, so a test can wait for it to be ready.
	RecordFile string   `json:"record_file"`
	Stdout     []string `json:"stdout"`
	Stderr     []string `json:"stderr"`
	// ExitAfter makes the fake exit with ExitCode after this delay. With
	// ExitOnceFile set it exits only on the run that creates that file.
	ExitAfter    time.Duration `json:"exit_after"`
	ExitCode     int           `json:"exit_code"`
	ExitOnceFile string        `json:"exit_once_file"`
	// HealthDelay delays binding the API, like telemt waiting for Telegram DCs.
	HealthDelay time.Duration `json:"health_delay"`
	NoAPI       bool          `json:"no_api"`
	ReadyStatus int           `json:"ready_status"` // default 200
	// SignalFile gets one line per SIGHUP received.
	SignalFile string `json:"signal_file"`
	// Lifetime bounds the fake so a broken test never leaves it running.
	Lifetime time.Duration `json:"lifetime"`
}

type fakeTelemtRecord struct {
	Args []string `json:"args"`
	Cwd  string   `json:"cwd"`
	PID  int      `json:"pid"`
}

// TestHelperFakeTelemt is not a real test: it is the fake telemt process.
func TestHelperFakeTelemt(t *testing.T) {
	optionsPath := os.Getenv(fakeTelemtEnv)
	if optionsPath == "" {
		t.Skip("helper process for the fake telemt; runs only when re-executed by a test")
	}
	os.Exit(runFakeTelemt(optionsPath, flag.Args()))
}

func runFakeTelemt(optionsPath string, args []string) int {
	raw, err := os.ReadFile(optionsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake telemt: bad options:", err)
		return 2
	}
	var f fakeTelemt
	if err := json.Unmarshal(raw, &f); err != nil {
		fmt.Fprintln(os.Stderr, "fake telemt: bad options:", err)
		return 2
	}

	if len(args) > 0 && args[0] == "--version" {
		version := f.Version
		if version == "" {
			version = "3.5.14"
		}
		fmt.Println("telemt " + version)
		return 0
	}

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	if f.RecordFile != "" {
		cwd, _ := os.Getwd()
		payload, _ := json.Marshal(fakeTelemtRecord{Args: args, Cwd: cwd, PID: os.Getpid()})
		tmp := f.RecordFile + ".tmp"
		if err := os.WriteFile(tmp, payload, 0o600); err == nil {
			_ = os.Rename(tmp, f.RecordFile)
		}
	}

	for _, line := range f.Stdout {
		fmt.Fprintln(os.Stdout, line)
	}
	for _, line := range f.Stderr {
		fmt.Fprintln(os.Stderr, line)
	}

	var exit <-chan time.Time
	if f.ExitAfter > 0 {
		firstRun := true
		if f.ExitOnceFile != "" {
			if _, err := os.Stat(f.ExitOnceFile); err == nil {
				firstRun = false
			} else {
				_ = os.WriteFile(f.ExitOnceFile, nil, 0o600)
			}
		}
		if firstRun {
			exit = time.After(f.ExitAfter)
		}
	}

	if !f.NoAPI && len(args) > 0 {
		go serveFakeTelemtAPI(f, args[len(args)-1])
	}

	lifetime := f.Lifetime
	if lifetime <= 0 {
		lifetime = time.Minute
	}
	deadline := time.After(lifetime)

	for {
		select {
		case <-hup:
			if f.SignalFile != "" {
				file, err := os.OpenFile(f.SignalFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
				if err == nil {
					_, _ = file.WriteString("SIGHUP\n")
					_ = file.Close()
				}
			}
		case <-exit:
			fmt.Fprintln(os.Stderr, "fake telemt exiting")
			return f.ExitCode
		case <-deadline:
			return 0
		}
	}
}

func serveFakeTelemtAPI(f fakeTelemt, configPath string) {
	if f.HealthDelay > 0 {
		time.Sleep(f.HealthDelay)
	}

	listen, err := fakeTelemtAPIListen(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake telemt:", err)
		os.Exit(1)
	}

	readyStatus := f.ReadyStatus
	if readyStatus == 0 {
		readyStatus = http.StatusOK
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"data":{"status":"ok","read_only":false},"revision":"r"}`))
	})
	mux.HandleFunc("/v1/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(readyStatus)
		if readyStatus == http.StatusOK {
			_, _ = w.Write([]byte(`{"ok":true,"data":{"ready":true,"status":"ready"},"revision":"r"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"data":{"ready":false,"status":"not_ready","reason":"no_healthy_upstreams"},"revision":"r"}`))
	})

	if err := http.ListenAndServe(listen, mux); err != nil {
		fmt.Fprintln(os.Stderr, "fake telemt: api:", err)
		os.Exit(1)
	}
}

// fakeTelemtAPIListen reads server.api.listen from the rendered config.
func fakeTelemtAPIListen(configPath string) (string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && section == "server.api" && strings.TrimSpace(key) == "listen" {
			return strconv.Unquote(strings.TrimSpace(value))
		}
	}
	return "", errors.New("server.api.listen not found in " + configPath)
}

// writeFakeTelemt writes a wrapper script that runs the fake telemt with
// options f and returns its path.
func writeFakeTelemt(t *testing.T, f fakeTelemt) string {
	t.Helper()

	payload, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	testBinary, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	optionsPath := filepath.Join(dir, "options.json")
	if err := os.WriteFile(optionsPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	script := fmt.Sprintf("#!/bin/sh\n%s=%s\nexport %s\nexec %s -test.run='^TestHelperFakeTelemt$' -- \"$@\"\n",
		fakeTelemtEnv, shellQuote(optionsPath), fakeTelemtEnv, shellQuote(testBinary))

	path := filepath.Join(dir, "telemt")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// readFakeTelemtRecord waits for the fake to write its record file.
func readFakeTelemtRecord(t *testing.T, path string) fakeTelemtRecord {
	t.Helper()

	var record fakeTelemtRecord
	waitFor(t, 10*time.Second, "the fake telemt record file", func() bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		return json.Unmarshal(data, &record) == nil
	})
	return record
}

// waitFor polls cond until it holds or the timeout passes.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for !cond() {
		select {
		case <-deadline.C:
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		case <-ticker.C:
		}
	}
}

func testNodeConfig(t *testing.T, executable string) *config.Config {
	t.Helper()
	return &config.Config{
		TelemtExecutablePath: executable,
		GeneratedConfigPath:  t.TempDir(),
		LogBufferSize:        500,
	}
}

func testMTConfig(t *testing.T) *Config {
	t.Helper()
	raw := fmt.Sprintf(`{"inbound_tag": "mtproto", "server": {"port": %d, "listeners": [{"ip": "127.0.0.1"}]}}`, netutil.FindFreePort())
	cfg, err := NewConfig(raw)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	return cfg
}

// lowerStartupTimeout sets telemtStartupTimeout for one test. Register it
// before the backend's Shutdown cleanup, so the restore runs after the
// supervisor goroutine has exited.
func lowerStartupTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()
	previous := telemtStartupTimeout
	telemtStartupTimeout = timeout
	t.Cleanup(func() { telemtStartupTimeout = previous })
}
