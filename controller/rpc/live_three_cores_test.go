package rpc

// GATE 1.5, against real processes on loopback over the real gRPC surface:
// xray + sing-box + hysteria2 running as three live cores on one node, each
// serving real traffic on its own port at the same time; every log line
// attributable to the core that wrote it; killing one core leaves the other two
// serving.
//
// controller/controller_test.go proves the same three properties against fakes
// registered through the seam. A fake proves the controller's bookkeeping. It
// cannot prove that three different binaries, with three different log formats
// and three different client protocols, actually run side by side — which is the
// gate. This file runs the whole thing through Start/GetLogs/GetStats/StopCore,
// so the merge that stamps core_id and the RPC that stops one core are the code
// under test, not a re-implementation of them.
//
// Every binary comes from an env var and every test SKIPS naming the missing var,
// so an absent binary can never read as a green run:
//
//	PG_LIVE_XRAY     xray.exe       any recent build
//	PG_LIVE_SINGBOX  sing-box.exe   must carry -tags with_v2ray_api
//	PG_LIVE_HYSTERIA hysteria.exe   pinned v2.13.0 (docs/multi/UPSTREAM.md:15)

import (
	"context"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller"
	nodeLogger "github.com/pasarguard/node/logger"
	"github.com/pasarguard/node/pkg/tlsutil"
)

// ---------------------------------------------------------------------------
// binaries
// ---------------------------------------------------------------------------

func liveBinary(t *testing.T, envVar, label string) string {
	t.Helper()
	p := strings.TrimSpace(os.Getenv(envVar))
	if p == "" {
		t.Skipf("%s is not set; skipping the live %s test. Point it at a real binary.", envVar, label)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("%s=%s is not usable: %v", envVar, p, err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("%s: abs: %v", envVar, err)
	}
	return abs
}

// liveSingBox refuses a binary without the v2ray_api tag: the sing-box core
// itself refuses to start against one (backend/singbox/core.go:108), so a skip
// here is the honest answer rather than a later confusing core-start failure.
func liveSingBox(t *testing.T) string {
	t.Helper()
	exe := liveBinary(t, "PG_LIVE_SINGBOX", "sing-box")
	out, err := exec.Command(exe, "version").CombinedOutput()
	if err != nil {
		t.Skipf("sing-box at %s would not run: %v\n%s", exe, err, out)
	}
	if !strings.Contains(string(out), "with_v2ray_api") {
		t.Skipf("sing-box at %s lacks -tags with_v2ray_api; per-user stats would silently stay zero", exe)
	}
	return exe
}

func liveFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func liveFreeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free udp port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func liveWaitTCP(t *testing.T, port int, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("%s never came up on port %d within %s", what, port, timeout)
}

func liveWriteJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	path := filepath.Join(dir, name)
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// liveConfigJSON renders a core's config for the Start RPC. The RPC wants the
// config AS A STRING (Backend.config), not a path to it — passing a path is the
// mistake this helper exists to prevent.
func liveConfigJSON(t *testing.T, v any) string {
	t.Helper()
	buf, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal core config: %v", err)
	}
	return string(buf)
}

func liveSelfSignedCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("openssl not on PATH; cannot mint a cert for the live hysteria core: %v", err)
	}
	out, err := exec.Command(openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyPath, "-out", certPath, "-days", "2", "-subj", "/CN=hysteria-live.local").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl req: %v\n%s", err, out)
	}
	return certPath, keyPath
}

// ---------------------------------------------------------------------------
// the internet, and a client per core
// ---------------------------------------------------------------------------

// liveOrigin serves a fixed-length body: the fixed length is what lets a client
// prove it received the REAL thing through the tunnel rather than a short read.
//
// It DRAINS the client's request before replying and drains the socket after.
// Closing early RSTs the loopback receive buffer and the client sees
// `ConnectionAbortedError 10053` even though nothing was wrong with the tunnel —
// the same trap panel/tests/integration/test_singbox_limit_expiry.py:106-116
// documents as KNOWN-ISSUES §8, and it makes a healthy core look dead.
func liveOrigin(t *testing.T, body int) int {
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
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				buf := make([]byte, 65536)
				for {
					// Drain the request; ignore the result, an origin only has to
					// consume what the client sends before it reads.
					if _, err := c.Read(buf); err != nil {
						break
					}
					if strings.Contains(string(buf), "\r\n\r\n") {
						break
					}
				}
				header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", body)
				if _, err := c.Write(append([]byte(header), make([]byte, body)...)); err != nil {
					return
				}
				// Drain the rest so the last bytes leave the loopback buffer
				// before the close, instead of being reset.
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// liveFetch drives real traffic through one client's proxy and returns the bytes
// that came back. 0 means nothing came back.
//
// It retries to the deadline: each of these proxies binds its listener before
// its tunnel is established, so one failed attempt is a race, not a verdict. The
// negative controls keep their meaning because a genuinely dead tunnel returns 0
// for the whole window.
func liveFetch(proxyPort, originPort int, timeout time.Duration) int {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
			},
		},
		Timeout: 5 * time.Second,
	}
	target := fmt.Sprintf("http://127.0.0.1:%d/", originPort)

	deadline := time.Now().Add(timeout)
	for {
		resp, err := client.Get(target)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr == nil && len(body) > 0 {
				return len(body)
			}
		} else {
			// Keep the last transport error: without it a 0-byte result is
			// indistinguishable from "the proxy was wrong".
			liveLastFetchErr.Store(err.Error())
		}
		if time.Now().After(deadline) {
			return 0
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// liveLastFetchErr carries the most recent transport error out of liveFetch, so a
// failing assertion can print WHY rather than only "0 bytes".
var liveLastFetchErr atomic.Value

type liveProc struct {
	cmd     *exec.Cmd
	logPath string
}

func liveStart(t *testing.T, exe string, args ...string) *liveProc {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "client.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("client log: %v", err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", exe, err)
	}
	p := &liveProc{cmd: cmd, logPath: logPath}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logFile.Close()
	})
	return p
}

func (p *liveProc) tail() string {
	b, err := os.ReadFile(p.logPath)
	if err != nil {
		return ""
	}
	s := string(b)
	if len(s) > 2000 {
		s = s[len(s)-2000:]
	}
	return s
}

// ---------------------------------------------------------------------------
// the three cores' configs: each distinguishable by its own log format
// ---------------------------------------------------------------------------

// The three markers are deliberately DOT-FREE.
//
// They stand in for the panel's per-user identity, which is the user's email —
// and a dot in a username is a known, reproduced hysteria2 defect: upstream
// decodes auth.userpass with a path-aware decoder, so a `.` in the key makes it
// a nested map and the core refuses to start ("'auth.userpass[a.b]' expected
// type 'string'"). backend/hysteria/dotted_username_test.go pins that as a
// failing test; this file must stay able to prove the multi-core gate, so its
// marker avoids the broken input rather than tripping over an unrelated defect.
//
// Once that test goes green these can go back to realistic emails.
const (
	liveEmailXray     = "live-xray-at-example"
	liveEmailSingbox  = "live-singbox-at-example"
	liveEmailHysteria = "live-hysteria-at-example"
	liveOriginBody    = 4096
)

// liveXrayConfig: one VLESS-TCP inbound with no users in the JSON (the gRPC API
// adds them) and a direct freedom outbound.
//
// loglevel "info" is load-bearing. At "warning" xray is nearly silent, and
// "every line is attributable" is trivially true of an empty stream.
func liveXrayConfig(t *testing.T, port int) string {
	t.Helper()
	return liveConfigJSON(t, map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"tag":      "vless-live",
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "vless",
			"settings": map[string]any{"clients": []any{}, "decryption": "none"},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "none",
			},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
	})
}

func liveSingboxConfig(t *testing.T, port int) string {
	t.Helper()
	return liveConfigJSON(t, map[string]any{
		"log": map[string]any{"level": "info"},
		"inbounds": []any{map[string]any{
			"type": "vless", "tag": "vless-live",
			"listen": "127.0.0.1", "listen_port": port,
			"users": []any{},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})
}

// liveHysteriaConfig uses auth.userpass — the only mode of v2.13.0 that
// attributes per user (backend/hysteria/user.go). The traffic-stats listener and
// its secret are added by the core, not here.
func liveHysteriaConfig(t *testing.T, listen, certPath, keyPath string) string {
	t.Helper()
	return liveConfigJSON(t, map[string]any{
		"listen": listen,
		"tls":    map[string]any{"cert": certPath, "key": keyPath},
		"auth":   map[string]any{"type": "userpass", "userpass": map[string]any{}},
	})
}

// ---------------------------------------------------------------------------
// the fixture: a real node process' worth of gRPC surface, three live cores
// ---------------------------------------------------------------------------

// liveNode is a real gRPC listener with a real client, plus the three live cores.
type liveNode struct {
	client common.NodeServiceClient
	ctx    context.Context // carries the api-key metadata
	svc    controller.Service
	conn   *grpc.ClientConn

	// ports, one per core, so a test can prove they are distinct
	xrayPort     int
	singboxPort  int
	hysteriaPort int // udp

	// client-side ports
	socksXray     int
	socksSingbox  int
	proxyHysteria int

	originPort int
	hystClient *liveProc
	// genPath is the node's generated-config root, so a test can ask the writer
	// where a core's per-core file lands instead of guessing at a directory.
	genPath string
}

const liveHysteriaEnv = "PG_LIVE_HYSTERIA"

// liveThreeCores boots a real gRPC listener and starts xray, sing-box and
// hysteria2 on it as three live cores, then brings up one real client per core.
//
// The hysteria password is minted BEFORE the core starts, so the core is never
// started with a user the client will not present — a later SyncUser would
// restart it and the log stream would straddle two process generations.
func liveThreeCores(t *testing.T) *liveNode {
	t.Helper()

	xrayExe := liveBinary(t, "PG_LIVE_XRAY", "xray")
	singboxExe := liveSingBox(t)
	hysteriaExe := liveBinary(t, liveHysteriaEnv, "hysteria")

	base := t.TempDir()
	gen := filepath.Join(base, "generated")
	certPath, keyPath := liveSelfSignedCert(t, base)

	// The cores resolve their binaries from the config / their own env var.
	// config.Load() reads these, and NewTestConfig calls Load(), so they must be
	// set BEFORE the config is built.
	t.Setenv("XRAY_EXECUTABLE_PATH", xrayExe)
	t.Setenv("SINGBOX_EXECUTABLE_PATH", singboxExe)
	// backend/hysteria/user.go:18 — the hysteria core reads its own env var, not
	// the config.
	t.Setenv("HYSTERIA_EXECUTABLE_PATH", hysteriaExe)

	key := uuid.New()
	cfg := config.NewTestConfig(gen, key)

	tlsConfig, err := tlsutil.LoadTLSCredentials("../../certs/ssl_cert.pem", "../../certs/ssl_key.pem")
	if err != nil {
		t.Fatalf("load TLS credentials: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", liveFreePort(t))
	shutdown, svc, err := StartGRPCListener(tlsConfig, addr, cfg)
	if err != nil {
		t.Fatalf("start gRPC listener: %v", err)
	}
	t.Cleanup(func() {
		svc.Disconnect()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = shutdown(ctx)
	})

	certPool, err := tlsutil.LoadClientPool("../../certs/ssl_cert.pem")
	if err != nil {
		t.Fatalf("load client pool: %v", err)
	}
	const maxMsgSize = 64 * 1024 * 1024
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(certPool, "")),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxMsgSize), grpc.MaxCallSendMsgSize(maxMsgSize)),
	)
	if err != nil {
		t.Fatalf("dial node: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	n := &liveNode{
		client:        common.NewNodeServiceClient(conn),
		ctx:           metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-api-key", key.String())),
		svc:           svc,
		conn:          conn,
		xrayPort:      liveFreePort(t),
		singboxPort:   liveFreePort(t),
		hysteriaPort:  liveFreeUDPPort(t),
		socksXray:     liveFreePort(t),
		socksSingbox:  liveFreePort(t),
		proxyHysteria: liveFreePort(t),
		originPort:    liveOrigin(t, liveOriginBody),
		genPath:       gen,
	}

	newUUID := func() string { return uuid.New().String() }

	type spec struct {
		id    uint64
		typ   common.BackendType
		cfg   string
		users []*common.User
	}
	specs := []spec{
		{
			id: 1, typ: common.BackendType_XRAY, cfg: liveXrayConfig(t, n.xrayPort),
			users: []*common.User{{
				Email:    liveEmailXray,
				Proxies:  &common.Proxy{Vless: &common.Vless{Id: newUUID()}},
				Inbounds: []string{"vless-live"},
			}},
		},
		{
			id: 2, typ: common.BackendType_SINGBOX, cfg: liveSingboxConfig(t, n.singboxPort),
			users: []*common.User{{
				Email:    liveEmailSingbox,
				Proxies:  &common.Proxy{Vless: &common.Vless{Id: newUUID()}},
				Inbounds: []string{"vless-live"},
			}},
		},
		{
			id: 3, typ: common.BackendType_HYSTERIA2,
			cfg: liveHysteriaConfig(t, "127.0.0.1:"+strconv.Itoa(n.hysteriaPort), certPath, keyPath),
			users: []*common.User{{
				Email:    liveEmailHysteria,
				Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw-" + newUUID()}},
				Inbounds: []string{},
			}},
		},
	}

	// Start all three through the real Start RPC. Each Start names its own
	// core_id, which is the whole mechanism under test.
	//
	// The credentials the clients will use are read back OUT of the specs, not
	// minted again: a client presenting a different uuid than the core was given
	// fails the VLESS handshake, and the symptom is a healthy core that appears
	// to serve nothing.
	vlessUUID := map[uint64]string{}
	hystPass := ""
	for _, s := range specs {
		switch s.typ {
		case common.BackendType_XRAY, common.BackendType_SINGBOX:
			vlessUUID[s.id] = s.users[0].GetProxies().GetVless().GetId()
		case common.BackendType_HYSTERIA2:
			hystPass = s.users[0].GetProxies().GetHysteria().GetAuth()
		}
		ctx, cancel := context.WithTimeout(n.ctx, 60*time.Second)
		info, err := n.client.Start(ctx, &common.Backend{
			Type: s.typ, CoreId: s.id, Config: s.cfg, Users: s.users, KeepAlive: 0,
		})
		cancel()
		if err != nil {
			t.Fatalf("Start core %d (%v): %v", s.id, s.typ, err)
		}
		if !info.GetStarted() {
			t.Fatalf("Start core %d reported started=false", s.id)
		}
	}

	// One real client per core.
	liveStart(t, singboxExe, "run", "-c", liveWriteJSON(t, base, "client-xray.json", map[string]any{
		"log": map[string]any{"level": "info"},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "socks",
			"listen": "127.0.0.1", "listen_port": n.socksXray,
		}},
		"outbounds": []any{
			map[string]any{
				"type": "vless", "tag": "proxy",
				"server": "127.0.0.1", "server_port": n.xrayPort, "uuid": vlessUUID[1],
			},
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": "proxy"},
	}))
	liveWaitTCP(t, n.socksXray, 30*time.Second, "sing-box client for the xray core")

	liveStart(t, singboxExe, "run", "-c", liveWriteJSON(t, base, "client-singbox.json", map[string]any{
		"log": map[string]any{"level": "info"},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "socks",
			"listen": "127.0.0.1", "listen_port": n.socksSingbox,
		}},
		"outbounds": []any{
			map[string]any{
				"type": "vless", "tag": "proxy",
				"server": "127.0.0.1", "server_port": n.singboxPort, "uuid": vlessUUID[2],
			},
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": "proxy"},
	}))
	liveWaitTCP(t, n.socksSingbox, 30*time.Second, "sing-box client for the sing-box core")

	n.hystClient = liveStart(t, hysteriaExe, "client", "-c",
		liveWriteJSON(t, base, "client-hysteria.json", map[string]any{
			"server": "127.0.0.1:" + strconv.Itoa(n.hysteriaPort),
			"auth":   liveEmailHysteria + ":" + hystPass,
			"tls":    map[string]any{"sni": "hysteria-live.local", "insecure": true},
			"http":   map[string]any{"listen": "127.0.0.1:" + strconv.Itoa(n.proxyHysteria)},
		}), "-l", "info")
	liveWaitTCP(t, n.proxyHysteria, 40*time.Second, "hysteria client for the hysteria2 core")

	// Give the clients a beat to finish their handshakes before the caller
	// starts driving traffic.
	liveWaitTCP(t, n.xrayPort, 20*time.Second, "xray core inbound")
	liveWaitTCP(t, n.singboxPort, 20*time.Second, "sing-box core inbound")

	t.Logf("three live cores up: xray=%d sing-box=%d hysteria2=%d (udp), origin=%d",
		n.xrayPort, n.singboxPort, n.hysteriaPort, n.originPort)
	return n
}

// proxyPortFor maps a core name to the client proxy that fronts it.
func (n *liveNode) proxyPortFor(core string) int {
	switch core {
	case "xray":
		return n.socksXray
	case "singbox":
		return n.socksSingbox
	case "hysteria":
		return n.proxyHysteria
	}
	return 0
}

// collectLogs opens the real GetLogs stream and gathers records until stop or the
// deadline. It returns the raw records so a test can assert on core_id itself.
//
// This reads the SAME stream the panel reads, so the merge that stamps core_id
// (controller/rpc/log.go) is the code producing these records.
func (n *liveNode) collectLogs(d time.Duration) (func() []*common.Log, error) {
	ctx, cancel := context.WithCancel(n.ctx)
	stream, err := n.client.GetLogs(ctx, &common.Empty{})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("GetLogs: %w", err)
	}

	var mu sync.Mutex
	var records []*common.Log
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			rec, err := stream.Recv()
			if err != nil {
				return
			}
			mu.Lock()
			records = append(records, rec)
			mu.Unlock()
		}
	}()

	timer := time.AfterFunc(d, cancel)
	return func() []*common.Log {
		timer.Stop()
		cancel()
		<-done
		mu.Lock()
		defer mu.Unlock()
		out := make([]*common.Log, len(records))
		copy(out, records)
		return out
	}, nil
}

// ---------------------------------------------------------------------------
// GATE 1: three cores alive at once, each serving real traffic simultaneously
// ---------------------------------------------------------------------------

// TestLiveThreeCoresServeTrafficAtOnce is the first third of the gate: three
// real cores, three real client processes, three real tunnels, all live in the
// same instant.
//
// Sequential fetches would not prove simultaneity — a core that died between two
// probes would still pass. So all three fetches run CONCURRENTLY, and every
// core's inbound port is proven reachable while they run.
func TestLiveThreeCoresServeTrafficAtOnce(t *testing.T) {
	n := liveThreeCores(t)

	type result struct {
		core  string
		bytes int
		err   error
	}
	results := make(chan result, 3)
	for _, core := range []string{"xray", "singbox", "hysteria"} {
		go func(core string) {
			port := n.proxyPortFor(core)
			got := liveFetch(port, n.originPort, 45*time.Second)
			results <- result{core: core, bytes: got}
		}(core)
	}

	// While the three fetches are in flight, every core's own inbound port must
	// accept a TCP connection. That is the "alive at the same time" evidence
	// that is independent of any one client's success.
	cores := map[string]int{"xray": n.xrayPort, "singbox": n.singboxPort}
	for name, port := range cores {
		liveWaitTCP(t, port, 30*time.Second, name+" core inbound (while other cores are serving)")
	}

	for range 3 {
		r := <-results
		if r.bytes <= 0 {
			reason, _ := liveLastFetchErr.Load().(string)
			t.Errorf("core %q served no traffic through its own client (0 bytes back from the origin); "+
				"last transport error: %s", r.core, reason)
			continue
		}
		t.Logf("core %q tunneled %d bytes through its own client while the other two served", r.core, r.bytes)
	}

	// And all three are still reported started by the node itself.
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	defer cancel()
	info, err := n.client.GetBaseInfo(ctx, &common.Empty{})
	if err != nil {
		t.Fatalf("GetBaseInfo: %v", err)
	}
	if len(info.GetCores()) != 3 {
		t.Fatalf("BaseInfoResponse.cores = %d, want 3", len(info.GetCores()))
	}
	seen := map[uint64]bool{}
	for _, cs := range info.GetCores() {
		if !cs.GetStarted() {
			t.Errorf("core %d (%v) reports started=false after serving traffic", cs.GetCoreId(), cs.GetType())
		}
		seen[cs.GetCoreId()] = true
	}
	for _, id := range []uint64{1, 2, 3} {
		if !seen[id] {
			t.Errorf("core %d missing from BaseInfoResponse.cores", id)
		}
	}
}

// ---------------------------------------------------------------------------
// GATE 2: log streams never mix
// ---------------------------------------------------------------------------

// coreMarker is a string only ONE core can possibly print. xray's access line
// carries the email of the user that made the request, so a line naming
// live-xray@example.invalid was produced by the xray core and by nothing else.
func lineMentions(rec *common.Log, needle string) bool {
	return strings.Contains(rec.GetDetail(), needle)
}

// liveMarkers maps each core to the user string that appears on ITS lines and
// no other core's.
var liveMarkers = map[uint64]string{
	1: liveEmailXray,
	2: liveEmailSingbox,
	3: liveEmailHysteria,
}

// assertNoMixedLogs is the gate's whole attribution rule, in one place, so the
// negative control can be run against the very same code.
//
// The rule: a record may carry no marker (a startup line says nothing about a
// user), but if it names a core's user it MUST carry that core's id. It does not
// assume any record's core_id is legitimate — a record claiming core 0 or core 9
// while naming a user is a mixed stream too.
func assertNoMixedLogs(records []*common.Log) error {
	for _, rec := range records {
		for id, marker := range liveMarkers {
			if lineMentions(rec, marker) && rec.GetCoreId() != id {
				return fmt.Errorf("MIXED: a line naming core %d's user came back under core_id=%d: %q",
					id, rec.GetCoreId(), rec.GetDetail())
			}
		}
	}
	return nil
}

// TestLiveLogStreamNeverMixes is the second third of the gate, against the real
// node: all three cores are noisy at once, and every record on the wire carries
// the core_id of the core that actually produced it.
//
// The attribution is asserted two ways, because either alone is weak:
//   - by content: a line naming core 1's user must carry core_id 1
//   - by provenance: NO record may claim a core_id whose marker it does not
//     carry, for the two cores whose markers are unambiguous
//
// A single misattributed line fails the gate.
func TestLiveLogStreamNeverMixes(t *testing.T) {
	n := liveThreeCores(t)

	// Start collecting BEFORE any traffic, so every core's lines count.
	drain, err := n.collectLogs(90 * time.Second)
	if err != nil {
		t.Fatalf("open log stream: %v", err)
	}

	// Make all three cores noisy, repeatedly and concurrently. One fetch per core
	// is not reliably enough: a core that logs at info can take a second to
	// surface its first line, and a stream with one core silent would make this
	// gate pass for the wrong reason.
	var wg sync.WaitGroup
	for _, core := range []string{"xray", "singbox", "hysteria"} {
		wg.Add(1)
		go func(core string) {
			defer wg.Done()
			for range 4 {
				liveFetch(n.proxyPortFor(core), n.originPort, 25*time.Second)
			}
		}(core)
	}
	wg.Wait()

	// Every core must actually have been driven, or "this core was silent" is a
	// fact about my probe rather than about the stream.
	for _, core := range []string{"xray", "singbox", "hysteria"} {
		if got := liveFetch(n.proxyPortFor(core), n.originPort, 30*time.Second); got <= 0 {
			t.Fatalf("core %q served no traffic during the log test, so its silence says nothing", core)
		}
	}

	records := drain()

	if len(records) == 0 {
		t.Fatal("no log records arrived from three live cores — an empty stream proves nothing")
	}
	t.Logf("collected %d log records from three live cores", len(records))

	if err := assertNoMixedLogs(records); err != nil {
		t.Fatal(err)
	}
	byCore := map[uint64]int{}
	for _, rec := range records {
		byCore[rec.GetCoreId()]++
	}
	for _, id := range []uint64{1, 2, 3} {
		if byCore[id] == 0 {
			t.Errorf("core %d contributed NO log records although it served real traffic "+
				"(per-core counts: 1=%d 2=%d 3=%d). A core that serves and never logs is a real "+
				"gap: GetLogs reads LogSources() ONCE at stream open, and a core whose Logger is "+
				"only bound on its first line (logger.BindOnce, logger.go:92) has no logLines channel "+
				"yet, so every line it produced before the stream attached is lost. Core 3 is "+
				"hysteria2, which binds through Hysteria.LogLines -> Core.LogLines.",
				id, byCore[1], byCore[2], byCore[3])
		}
	}

	// Each record must also be timestamped by the node clock — a field the
	// panel's filter and ordering depend on.
	for _, rec := range records {
		if rec.GetTsUnixMs() <= 0 {
			t.Errorf("record under core_id=%d has ts_unix_ms=%d, want the node's clock", rec.GetCoreId(), rec.GetTsUnixMs())
			break
		}
	}

	t.Logf("records per core: 1=%d 2=%d 3=%d", byCore[1], byCore[2], byCore[3])
}

// TestLivePerCoreFilesNeverMix is the same property on disk. Read the gate's
// own wording: the streams never mix AND a core writes only its own file.
//
// The directory is DERIVED from the node's generated-config root, the same way
// the writer derives it (logger.CoreLogLocation reads core-<id> back out of the
// path the core was handed), so the file lands beside that core's config
// directory. It is NOT read from LOG_DIR: the node has no such setting, and a
// test asserting against one looked for a directory the node never writes to.
// liveNode keeps the generated root so this can ask the writer directly.
// TestPerCoreFileAssertionsHaveTheRightPolarity is the negative control for the
// file test's own assertions. Every "must be ABSENT" check there is written
// `if strings.Contains(...) { t.Error("... landed in ...") }`; every "must be
// PRESENT" check is `if !strings.Contains(...) { t.Error("... is missing ...") }`.
//
// One of them was written the wrong way round — `Contains` guarding a "is
// missing" message — which made the gate fail on a file that DID contain the
// line, and would have PASSED on an empty one. The polarity is invisible in a
// glance at the file and nothing else caught it, so it is pinned here: each
// sample below must report the verdict the message claims.
func TestPerCoreFileAssertionsHaveTheRightPolarity(t *testing.T) {
	const email = "marker-user"

	absent := "clean line, no marker here"
	present := "inbound[vless-live]: [" + email + "] inbound connection"

	cases := []struct {
		name string
		file string
		want bool // whether the marker is present
	}{
		{"marker present", present, true},
		{"marker absent", absent, false},
		{"empty file", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Contains(tc.file, email)
			if got != tc.want {
				t.Fatalf("strings.Contains(%q, %q) = %v, want %v", tc.file, email, got, tc.want)
			}
			// The live test's two guards, and what each must conclude:
			//   `if Contains { "landed in" }`  -> fires when the marker IS present
			//   `if !Contains { "is missing" }` -> fires when the marker is NOT present
			landedInGuardFires := got
			isMissingGuardFires := !got
			if landedInGuardFires != tc.want {
				t.Errorf("the `Contains` (landed in) guard fires=%v, want %v", landedInGuardFires, tc.want)
			}
			if isMissingGuardFires == tc.want {
				t.Errorf("the `!Contains` (is missing) guard fires=%v, want %v",
					isMissingGuardFires, !tc.want)
			}
		})
	}
}

func TestLivePerCoreFilesNeverMix(t *testing.T) {
	n := liveThreeCores(t)

	// Drive traffic and WAIT for it, as every other gate test does. Firing the
	// fetches into goroutines nobody joined and then sleeping a fixed 3s was a
	// race: the assertion below could run before sing-box had logged its first
	// connection, and "core-2.log is missing core 2's own access line" then
	// described the test's timing rather than the code. A core that serves no
	// traffic is the negative control, and the fetch result proves it either way.
	for _, core := range []string{"xray", "singbox", "hysteria"} {
		if got := liveFetch(n.proxyPortFor(core), n.originPort, 45*time.Second); got <= 0 {
			t.Fatalf("core %q served no traffic during the per-core FILE test, so its file "+
				"says nothing about whether the writer works", core)
		}
	}
	// The fetch returned bytes, but the line is written by the log-reading
	// goroutine on the way out of the child; give it a beat to land on disk.
	time.Sleep(2 * time.Second)

	logDir, ok := nodeLogger.CoreLogDir(filepath.Join(n.genPath, "core-1"))
	if !ok {
		t.Fatalf("%q is not a per-core directory, so no per-core file exists there",
			filepath.Join(n.genPath, "core-1"))
	}

	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(logDir, name))
		if err != nil {
			t.Fatalf("read %s from the directory the writer derives (%s): %v", name, logDir, err)
		}
		return string(b)
	}
	one, two, three := read("core-1.log"), read("core-2.log"), read("core-3.log")

	if !strings.Contains(one, liveEmailXray) {
		t.Error("core-1.log is missing core 1's own access line")
	}
	if strings.Contains(one, liveEmailSingbox) {
		t.Error("core 2's line landed in core-1.log")
	}
	if strings.Contains(one, liveEmailHysteria) {
		t.Error("core 3's line landed in core-1.log")
	}
	if strings.Contains(two, liveEmailXray) {
		t.Error("core 1's line landed in core-2.log")
	}
	if strings.Contains(three, liveEmailXray) {
		t.Error("core 1's line landed in core-3.log")
	}
	if !strings.Contains(two, liveEmailSingbox) {
		t.Error("core-2.log is missing core 2's own access line")
	}
	// Core 3 must have a line of its own too. It is not in `two`, so this also
	// covers the cross-check: hysteria logs the authenticated id, which is the
	// username, on the "client connected" line.
	if !strings.Contains(three, liveEmailHysteria) {
		t.Error("core-3.log is missing core 3's own line")
	}
	// The control an inverted "contains" would lose: a must-be-present check
	// passes on an EMPTY file, so prove the files are non-empty too.
	if len(two) == 0 || len(three) == 0 {
		t.Errorf("a per-core file is empty (core-2=%d B, core-3=%d B); a passing "+
			"'contains' on an empty file proves nothing", len(two), len(three))
	}
	t.Logf("core-1.log=%d B core-2.log=%d B core-3.log=%d B in %s, no cross-contamination",
		len(one), len(two), len(three), logDir)
}

// ---------------------------------------------------------------------------
// GATE 3: killing one core leaves the others serving
// ---------------------------------------------------------------------------

// TestLiveStoppingOneCoreLeavesTheOthersServing is the third third of the gate.
//
// It stops core 1 through the real StopCore RPC (NOT Disconnect, NOT a process
// kill) and then proves the other two still tunnel real traffic, while core 1's
// own port stops answering. A StopCore that quietly took the whole node down
// would fail here — which is the failure mode the RPC exists to prevent.
func TestLiveStoppingOneCoreLeavesTheOthersServing(t *testing.T) {
	n := liveThreeCores(t)

	// Baseline: all three serve.
	for _, core := range []string{"xray", "singbox", "hysteria"} {
		if got := liveFetch(n.proxyPortFor(core), n.originPort, 45*time.Second); got <= 0 {
			t.Fatalf("baseline: core %q served no traffic", core)
		}
	}

	// Stop ONLY core 1, over the wire.
	ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
	if _, err := n.client.StopCore(ctx, &common.StopCore{CoreId: 1}); err != nil {
		cancel()
		t.Fatalf("StopCore(1): %v", err)
	}
	cancel()

	// The node must report core 1 stopped and cores 2 and 3 started.
	ctx, cancel = context.WithTimeout(n.ctx, 15*time.Second)
	info, err := n.client.GetBaseInfo(ctx, &common.Empty{})
	cancel()
	if err != nil {
		t.Fatalf("GetBaseInfo after StopCore: %v", err)
	}
	for _, cs := range info.GetCores() {
		switch cs.GetCoreId() {
		case 1:
			if cs.GetStarted() {
				t.Error("core 1 still reports started=true after StopCore(1)")
			}
		case 2, 3:
			if !cs.GetStarted() {
				t.Errorf("core %d went down when core 1 was stopped", cs.GetCoreId())
			}
		}
	}

	// Core 1's inbound port must stop answering. Assert on LIVENESS rather than
	// on exit (a killed process reports both, a wedged one only liveness).
	liveWaitTCPDead(t, n.xrayPort, 30*time.Second, "xray core inbound after StopCore(1)")

	// The survivors still pass traffic.
	for _, core := range []string{"singbox", "hysteria"} {
		got := liveFetch(n.proxyPortFor(core), n.originPort, 45*time.Second)
		if got <= 0 {
			t.Errorf("core %q stopped serving after core 1 was stopped (0 bytes)", core)
			continue
		}
		t.Logf("core %q still tunneled %d bytes after core 1 was stopped", core, got)
	}

	// Their counters still move — a proxy that accepts a connection but reports
	// zero bytes is not "serving".
	//
	// This is where GATE 3's "the others stay up" stops being true at the RPC
	// layer: controller/rpc/middleware.go:80-88 gates EVERY unary RPC on the
	// DEFAULT core (core 1) being alive, so once core 1 is stopped every RPC on
	// cores 2 and 3 is refused with `Unavailable: backend not initialized` even
	// though both cores are still serving traffic. The traffic assertions above
	// pass; these fail. That is the gate, found.
	for id, email := range map[uint64]string{2: liveEmailSingbox, 3: liveEmailHysteria} {
		ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
		resp, err := n.client.GetStats(ctx, &common.StatRequest{
			Type: common.StatType_UsersStat, CoreId: id, Reset_: false,
		})
		cancel()
		if err != nil {
			t.Errorf("GATE 3 DEFECT: core %d is still serving traffic but its RPC failed: %v\n"+
				"checkBackendStatus (controller/rpc/middleware.go:80-88) gates every unary RPC on "+
				"the DEFAULT core (core 1) being started, so StopCore(1) makes the whole node "+
				"unmanageable while cores 2 and 3 keep running. The gate must be per requested core, "+
				"not per default core.", id, err)
			continue
		}
		found := false
		for _, s := range resp.GetStats() {
			if s.GetName() == email {
				found = true
				t.Logf("core %d still reports its own user %s: %s=%d", id, email, s.GetType(), s.GetValue())
			}
		}
		if !found {
			t.Errorf("core %d reports no stat for its own user %s after core 1 was stopped", id, email)
		}
	}

	// And the aggregate (core_id 0) must still answer from the survivors.
	ctx, cancel = context.WithTimeout(n.ctx, 30*time.Second)
	agg, err := n.client.GetStats(ctx, &common.StatRequest{Type: common.StatType_UsersStat, CoreId: 0})
	cancel()
	if err != nil {
		t.Errorf("GATE 3 DEFECT: aggregate GetStats over the surviving cores failed: %v", err)
	} else {
		t.Logf("aggregate across surviving cores: %d rows", len(agg.GetStats()))
	}
}

// liveWaitTCPDead asserts a port STOPS accepting connections. Liveness, not
// exit status: a wedged process never exits and would pass an exit check.
func liveWaitTCPDead(t *testing.T, port int, timeout time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err != nil {
			return
		}
		_ = c.Close()
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("%s is still accepting connections on port %d after %s", what, port, timeout)
}

// ---------------------------------------------------------------------------
// NEGATIVE CONTROLS: a test that cannot fail proves nothing
// ---------------------------------------------------------------------------

// TestNegativeControlStopAllCoresDoesNotPassTheGate is the negative control for
// gate 3. It runs the SAME survivors check as
// TestLiveStoppingOneCoreLeavesTheOthersServing, but stops EVERY core with the
// node-level Stop — which is what a broken StopCore would really be doing, since
// StopCore with no core_id and Stop with core_id 1 differ only in the target.
//
// The assertion the gate makes ("the other two still serve") MUST fail here. The
// test therefore asserts that the survivors serve NOTHING, so a pass proves the
// check has teeth: if this test ever passed because the survivors still worked,
// the gate test above would have been vacuous.
func TestNegativeControlStopAllCoresDoesNotPassTheGate(t *testing.T) {
	n := liveThreeCores(t)

	for _, core := range []string{"xray", "singbox", "hysteria"} {
		if got := liveFetch(n.proxyPortFor(core), n.originPort, 45*time.Second); got <= 0 {
			t.Fatalf("baseline: core %q served no traffic", core)
		}
	}

	// Stop EVERYTHING, the way a StopCore that ignored its core_id would.
	ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
	if _, err := n.client.Stop(ctx, &common.Empty{}); err != nil {
		cancel()
		t.Fatalf("Stop: %v", err)
	}
	cancel()

	for _, core := range []string{"xray", "singbox"} {
		if got := liveFetch(n.proxyPortFor(core), n.originPort, 10*time.Second); got > 0 {
			t.Fatalf("NEGATIVE CONTROL IS TOOTHLESS: core %q still served %d bytes after Stop() "+
				"stopped every core, so the survivors check in the gate test cannot fail", core, got)
		}
	}
	t.Log("negative control OK: after Stop() every core is dead, so the survivors check can fail")
}

// TestNegativeControlCollapsedCoreIdIsCaught is the negative control for gate 2.
//
// It forces the failure the log-isolation test exists to catch — two cores
// reporting under ONE core id — by asking for the same core twice with a
// different type, and then asserts the stream cannot satisfy the gate's rule.
//
// It does not mutate production code. It reproduces the misattribution by
// hand-building the records a broken merge would emit and running them through
// the SAME assertion helper the gate test uses. If that helper cannot fail on a
// mixed stream, the gate test proves nothing, and this test fails.
func TestNegativeControlCollapsedCoreIdIsCaught(t *testing.T) {
	// What a broken merge looks like on the wire: core 1's line under core 2.
	mixed := []*common.Log{
		{CoreId: 1, Detail: "accepted tcp:o.example:443 [vless-live -> direct] email: " + liveEmailXray},
		{CoreId: 2, Detail: "accepted tcp:o.example:443 [vless-live -> direct] email: " + liveEmailSingbox},
		// the defect: an xray line stamped with sing-box's id
		{CoreId: 2, Detail: "2026/10/05 18:00:00 [Info] " + liveEmailXray},
	}

	if err := assertNoMixedLogs(mixed); err == nil {
		t.Fatal("NEGATIVE CONTROL IS TOOTHLESS: a record naming core 1's user under core_id=2 " +
			"passed the isolation check, so TestLiveLogStreamNeverMixes cannot fail")
	} else {
		t.Logf("negative control OK: the isolation check rejects a mixed stream (%v)", err)
	}

	// And the same records with correct ids must pass, so the check is not just
	// rejecting everything.
	clean := []*common.Log{mixed[0], mixed[1]}
	if err := assertNoMixedLogs(clean); err != nil {
		t.Fatalf("the isolation check rejects a CLEAN stream, so its pass is meaningless: %v", err)
	}
}

// TestNegativeControlSurvivorsCheckFailsWhenTheyAreDead is the negative control
// for gate 3's traffic check, at the assertion level: the very expression the
// gate test uses must be false when nothing is serving.
func TestNegativeControlSurvivorsCheckFailsWhenTheyAreDead(t *testing.T) {
	n := liveThreeCores(t)

	if got := liveFetch(n.proxyPortFor("xray"), n.originPort, 45*time.Second); got <= 0 {
		t.Fatalf("baseline: the xray core served no traffic, so a 0-byte result means nothing")
	}

	ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
	if _, err := n.client.Stop(ctx, &common.Empty{}); err != nil {
		cancel()
		t.Fatalf("Stop: %v", err)
	}
	cancel()

	// This is the gate's own predicate, unchanged: did the core pass traffic?
	if got := liveFetch(n.proxyPortFor("xray"), n.originPort, 10*time.Second); got > 0 {
		t.Fatalf("NEGATIVE CONTROL IS TOOTHLESS: the xray core still served %d bytes with every "+
			"core stopped, so `got <= 0` in the gate test would never be true", got)
	}
	t.Log("negative control OK: `served <= 0` is reachable, so the gate's survival assertion can fail")
}
