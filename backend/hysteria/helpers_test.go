package hysteria

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The tests below drive a real hysteria2 server and a real hysteria2 client
// over loopback. The binary is the pinned v2.13.0 (docs/multi/UPSTREAM.md:15,
// sha256 162ef8fe…f067); point HYSTERIA_TEST_BINARY at it. Without it every
// test skips with that reason — never silently.

const pinnedVersion = "2.13.0"

func hysteriaBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv("HYSTERIA_TEST_BINARY")
	if path == "" {
		t.Skipf("HYSTERIA_TEST_BINARY is not set; skipping the live hysteria %s loopback test. "+
			"Fetch the pinned binary (docs/multi/UPSTREAM.md) and set HYSTERIA_TEST_BINARY to it.", pinnedVersion)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("HYSTERIA_TEST_BINARY=%s is not usable: %v", path, err)
	}
	return path
}

// requirePinnedBinary is the guard against testing against some other build.
// Everything the tests assert about hysteria's behaviour — the "user" id from
// password auth, /traffic?clear=1 semantics, salamander — is version-specific,
// so a silently different binary would make a green run meaningless.
func requirePinnedBinary(t *testing.T) string {
	t.Helper()
	exe := hysteriaBinary(t)

	out, err := exec.Command(exe, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("hysteria version failed: %v\n%s", err, out)
	}
	m := versionRe.FindStringSubmatch(string(out))
	if len(m) < 2 {
		t.Fatalf("could not parse hysteria version from:\n%s", out)
	}
	if !strings.HasPrefix(m[1], pinnedVersion) {
		t.Skipf("binary is v%s, tests pin v%s; skipping rather than asserting version-specific behaviour", m[1], pinnedVersion)
	}
	return exe
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free udp port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// writeSelfSignedCert produces the TLS material a hysteria server needs. It
// shells out to openssl rather than embedding a certificate: a checked-in cert
// with a fixed expiry is a test that starts failing on a date nobody remembers.
func writeSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("openssl not on PATH; cannot generate the TLS material hysteria requires: %v", err)
	}

	// MSYS_NO_PATHCONV: Git-Bash rewrites a /CN=... argument into a Windows path,
	// which openssl then rejects as a malformed subject.
	cmd := exec.Command(openssl, "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyPath, "-out", certPath,
		"-days", "2", "-nodes",
		"-subj", "/CN=hysteria-test.local",
		"-addext", "subjectAltName=DNS:hysteria-test.local,IP:127.0.0.1")
	cmd.Env = append(os.Environ(), "MSYS_NO_PATHCONV=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("openssl failed to generate a test certificate: %v\n%s", err, out)
	}
	return certPath, keyPath
}

// serverConfigJSON builds a hysteria server config the backend can load.
//
// One detail matters and is easy to get wrong: masquerade requires BOTH
// listenHTTP and listenHTTPS ("having only HTTP server without HTTPS is not
// supported", verified against v2.13.0). A test that sets only one gets a
// config that hysteria rejects outright.
func serverConfigJSON(listen string, certPath, keyPath string, extra map[string]any) string {
	cfg := map[string]any{
		"listen": listen,
		"tls":    map[string]any{"cert": certPath, "key": keyPath},
		"auth": map[string]any{
			"type":     "userpass",
			"userpass": map[string]any{},
		},
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return mustJSON(cfg)
}

func mustJSON(v any) string {
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(buf)
}

// startHTTPOrigin serves a fixed-length HTTP body, so the client test uses a
// real proxy protocol rather than a raw CONNECT.
func startHTTPOrigin(t *testing.T, body int) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", body)
				_, _ = c.Write(append([]byte(header), make([]byte, body)...))
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// hysteriaClient starts a real hysteria2 client with an HTTP proxy listener and
// waits for the listener. Returns its log path so a failed assertion can show
// why.
//
// waitForProxy is false for a client that is EXPECTED to fail: hysteria's client
// connects eagerly and exits when the handshake is refused, so its proxy
// listener never appears and waiting for it would turn a correct negative
// control into a timeout.
func hysteriaClient(t *testing.T, exe, configPath string, proxyPort int, waitForProxy bool) string {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "client.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("client log: %v", err)
	}
	cmd := exec.Command(exe, "client", "-c", configPath, "-l", "info")
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		t.Fatalf("start hysteria client: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
	})

	if waitForProxy {
		if err := waitForTCPPort(proxyPort, 20*time.Second); err != nil {
			t.Fatalf("hysteria client proxy never came up: %v\n%s", err, tailFile(t, logPath))
		}
	} else {
		time.Sleep(4 * time.Second)
	}
	return logPath
}

func clientConfigJSON(server string, auth string, proxyPort int, extra map[string]any) string {
	cfg := map[string]any{
		"server": server,
		"auth":   auth,
		"tls":    map[string]any{"sni": "hysteria-test.local", "insecure": true},
		"http":   map[string]any{"listen": "127.0.0.1:" + strconv.Itoa(proxyPort)},
	}
	for k, v := range extra {
		cfg[k] = v
	}
	return mustJSON(cfg)
}

func waitForTCPPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %d not reachable within %s", port, timeout)
}

// httpGetViaProxy issues a real HTTP GET through the client's proxy and returns
// the body length. A length of 0 means nothing came back, which is how a failed
// tunnel shows up.
//
// It retries until deadline because hysteria's client binds its proxy listener
// BEFORE the QUIC tunnel is established: a port check alone races the handshake,
// and one unlucky run fails on timing rather than on the thing under test. A
// refused credential still returns 0 for the whole window, so the negative
// controls keep their meaning.
func httpGetViaProxy(proxyPort, targetPort int, timeout time.Duration) int {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
			},
		},
		Timeout: 5 * time.Second,
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/", targetPort)

	deadline := time.Now().Add(timeout)
	for {
		resp, err := client.Get(url)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr == nil && len(body) > 0 {
				return len(body)
			}
		}
		if time.Now().After(deadline) {
			return 0
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func tailFile(t *testing.T, path string) string {
	t.Helper()
	buf, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(lines) > 15 {
		lines = lines[len(lines)-15:]
	}
	return strings.Join(lines, "\n")
}

// writeClientConfig writes a client config and returns its path.
func writeClientConfig(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// probeMasquerade fetches a masquerade listener and returns the body plus the
// Alt-Svc header, which is how hysteria advertises its QUIC port to a client.
func probeMasquerade(t *testing.T, url string) (body, altSvc string) {
	t.Helper()
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// The masquerade HTTPS listener serves the decoy cert, not ours.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("probe %s: %v", url, err)
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return string(buf), resp.Header.Get("Alt-Svc")
}

// startStreamingOrigin serves an endless body, one chunk at a time, so a test
// can hold an ESTABLISHED tunnel open and watch it die. A fixed-length body
// would finish before the kick and prove nothing.
func startStreamingOrigin(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n"))
				chunk := make([]byte, 1024)
				for i := range chunk {
					chunk[i] = 'x'
				}
				for {
					if _, err := c.Write(chunk); err != nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// openStreamThroughProxy starts a GET through the client's proxy and returns
// the live response, having already read enough bytes to prove the tunnel is
// carrying data.
func openStreamThroughProxy(t *testing.T, proxyPort, targetPort int) *http.Response {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
			},
		},
	}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", targetPort))
	if err != nil {
		t.Fatalf("open stream through the tunnel: %v", err)
	}
	buf := make([]byte, 1024)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		_ = resp.Body.Close()
		t.Fatalf("stream carried no data before the kick: %v", err)
	}
	return resp
}

func containsAll(haystack string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(haystack, needle) {
			return false
		}
	}
	return true
}

// rawStatsStatus hits the traffic stats API with a caller-chosen Authorization
// value, bypassing the node's own client, so a test can prove which secret the
// core actually accepts.
func rawStatsStatus(apiPort int, secret string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/traffic", apiPort), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", secret)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}
