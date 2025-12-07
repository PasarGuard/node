//go:build !windows

package xray

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFindXrayProcessesMultiple(t *testing.T) {
	exe := resolveXrayBinary(t)

	const instanceCount = 5
	children := make([]struct {
		pid    int
		waitCh <-chan error
	}, 0, instanceCount)

	for i := 0; i < instanceCount; i++ {
		pid, waitCh := startXrayProcess(t, exe)
		children = append(children, struct {
			pid    int
			waitCh <-chan error
		}{pid: pid, waitCh: waitCh})
	}

	waitForProcesses(exe, children, t)

	for _, c := range children {
		if err := killProcessTree(c.pid); err != nil {
			t.Fatalf("killProcessTree(%d) error: %v", c.pid, err)
		}
	}

	for _, c := range children {
		select {
		case <-c.waitCh:
		case <-time.After(5 * time.Second):
			t.Fatalf("xray process %d did not exit after kill", c.pid)
		}
	}
}

func keys(m map[int]struct{}) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func resolveXrayBinary(t *testing.T) string {
	t.Helper()

	candidates := []string{}
	if envPath := os.Getenv("XRAY_EXECUTABLE_PATH"); envPath != "" {
		candidates = append(candidates, envPath)
	}
	candidates = append(candidates, "/usr/local/bin/xray")

	for _, path := range candidates {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path
		}
	}

	t.Skip("xray binary not found; set XRAY_EXECUTABLE_PATH to a valid xray executable")
	return ""
}

func startXrayProcess(t *testing.T, exe string) (pid int, waitCh <-chan error) {
	t.Helper()

	configPath := writeMinimalXrayConfig(t)

	cmd := exec.Command(exe, "-c", configPath)
	cmd.Env = append(os.Environ(), XrayEnv()...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start real xray (%s): %v", exe, err)
	}

	wait := make(chan error, 1)
	go func() {
		wait <- cmd.Wait()
	}()

	// Ensure it didn't exit immediately
	select {
	case err := <-wait:
		t.Fatalf("xray exited early: %v", err)
	default:
	}

	t.Cleanup(func() {
		_ = killProcessTree(cmd.Process.Pid)
		select {
		case <-wait:
		case <-time.After(time.Second):
		}
	})

	return cmd.Process.Pid, wait
}

func writeMinimalXrayConfig(t *testing.T) string {
	t.Helper()

	port := reservePort(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "xray.json")

	cfg := fmt.Sprintf(`{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "socks",
    "settings": {"auth": "noauth", "udp": false}
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}`, port)

	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatalf("failed to write xray config: %v", err)
	}

	return cfgPath
}

func reservePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}
	defer l.Close()

	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected addr type %T", l.Addr())
	}
	return addr.Port
}

func XrayEnv() []string {
	env := []string{}

	assets := os.Getenv("XRAY_ASSETS_PATH")
	if assets == "" {
		if _, err := os.Stat("/usr/local/share/xray"); err == nil {
			assets = "/usr/local/share/xray"
		}
	}

	if assets != "" {
		env = append(env, "XRAY_LOCATION_ASSET="+assets)
	}

	return env
}

func waitForProcesses(exe string, children []struct {
	pid    int
	waitCh <-chan error
}, t *testing.T) {
	t.Helper()

	want := make(map[int]struct{}, len(children))
	for _, c := range children {
		want[c.pid] = struct{}{}
	}

	for i := 0; i < 20 && len(want) > 0; i++ {
		procs, err := findXrayProcesses(exe)
		if err != nil {
			t.Fatalf("findXrayProcesses returned error: %v", err)
		}
		for _, p := range procs {
			delete(want, p.PID)
		}

		if len(want) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	if len(want) > 0 {
		t.Fatalf("missing xray PIDs in process list after wait: %v", keys(want))
	}
}

func TestFindXrayProcessesReturnsEmptyWhenNoMatch(t *testing.T) {
	// Use a clearly non-existent executable path; expect empty results, no error.
	procs, err := findXrayProcesses("/nonexistent/xray/path/doesnotexist")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(procs) != 0 {
		t.Fatalf("expected zero processes, got %d", len(procs))
	}
}
