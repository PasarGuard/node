package chisel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/backend/tunnel/tunneltest"
)

// testPath and testHeader are deliberately not "/" and not absent: the whole
// point of the path/header checks is that the rendered values reach the wire.
const (
	testPath   = "/pg-chisel-3.2a"
	testHeader = "X-PG-Test: chisel"
)

// setBundle points TUNNEL_BUNDLE_DIR at an offline bundle that actually holds
// a pin-matching chisel, and fails (never skips) when this host has none:
// every chisel test needs the pinned binary, and a test that silently passed
// without it would prove nothing.
func setBundle(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("TUNNEL_BUNDLE_DIR")
	if dir == "" {
		// <repo>/../../tunnel-bundle when the node worktree sits next to it,
		// and the documented bundle path on the test server.
		for _, candidate := range []string{
			filepath.Join("..", "..", "..", "tunnel-bundle"),
			"/opt/tunnel-bundle",
		} {
			if st, err := os.Stat(candidate); err == nil && st.IsDir() {
				dir = candidate
				break
			}
		}
	}
	if dir == "" {
		t.Fatal("no offline chisel bundle: set TUNNEL_BUNDLE_DIR (tried ../../../tunnel-bundle and /opt/tunnel-bundle)")
	}
	if _, err := tunnel.ResolveBinary(Tool, dir); err != nil {
		t.Fatalf("bundle %s does not hold a pin-matching chisel: %v", dir, err)
	}
	t.Setenv("TUNNEL_BUNDLE_DIR", dir)
	return dir
}

func portOf(addr string) int {
	_, raw, err := net.SplitHostPort(addr)
	if err != nil {
		panic("endpoint " + addr + ": " + err.Error())
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		panic("endpoint " + addr + ": " + err.Error())
	}
	return port
}

// newSpec is the kit's factory: it builds each side's Spec from the endpoints
// the kit allocated. In production both sides receive the same Params from the
// tunnel row, so every key is set for both sides and each side reads what it
// needs — here they are filled per side only for clarity.
func newSpec(mode string) func(tunneltest.Endpoints) tunnel.Spec {
	return func(e tunneltest.Endpoints) tunnel.Spec {
		params := map[string]string{
			tunnel.ParamListenPort: strconv.Itoa(portOf(e.Listen)),
			paramListenHost:        "127.0.0.1",
			paramPath:              testPath,
			paramPeer:              e.Peer,
			paramTarget:            e.Target,
		}
		if mode == tunnel.ModeReverse {
			// The published port is a third bind on side A's host. Side B
			// names it in the reverse remote, side A's shim dials it: in this
			// loopback run it shares the far side's allocated port number.
			if e.Side == tunnel.SideA {
				params[paramPublishPort] = strconv.Itoa(portOf(e.Peer))
			} else {
				params[paramPublishPort] = strconv.Itoa(portOf(e.Listen))
			}
		}
		return tunnel.Spec{
			TunnelID:    e.TunnelID,
			Tool:        Tool,
			ToolVersion: Version,
			Side:        e.Side,
			Mode:        mode,
			Params:      params,
			Secrets:     map[string]string{SecretAuth: ""},
			Enabled:     true,
		}
	}
}

func runKit(t *testing.T, mode string) {
	t.Helper()
	// chisel's --auth is "user:pass"; a value without a username is refused by
	// the adapter before anything starts, so the good secret has to be one too.
	t.Setenv(SecretAuth, "kit-"+mode+":secret-9x")
	setBundle(t)
	alloc := tunnel.NewAllocator()
	tunneltest.Run(t, tunneltest.Kit{
		Adapter:  Adapter{},
		NewSpec:  newSpec(mode),
		Allocate: func() tunnel.Ports { return alloc.AllocPair() },
		Corrupt: func(s *tunnel.Spec) {
			if s.Secrets == nil {
				s.Secrets = map[string]string{}
			}
			s.Secrets[SecretAuth] = "wrong:credential"
		},
	})
}

// TestFourPartRelay is the four-part testkit in mode=relay: traffic,
// restart, a wrong credential refused, log isolation — no skips.
func TestFourPartRelay(t *testing.T) { runKit(t, tunnel.ModeRelay) }

// TestFourPartReverse is the same four parts in mode=reverse, which is a
// different process topology (side A runs the server, side B dials out), so
// it needs its own run: a relay pass says nothing about reverse.
func TestFourPartReverse(t *testing.T) { runKit(t, tunnel.ModeReverse) }

// ------------------------------------------------------------------ render

func renderSpec(side tunnel.Side, mode string, params map[string]string) tunnel.Spec {
	base := map[string]string{
		tunnel.ParamListenPort: "18080",
		paramListenHost:        "127.0.0.1",
		paramPath:              testPath,
		paramPeer:              "192.0.2.10:18080",
		paramTarget:            "192.0.2.20:5432",
		paramPublishPort:       "19000",
	}
	for k, v := range params {
		base[k] = v
	}
	return tunnel.Spec{
		TunnelID: "render-1",
		Tool:     Tool,
		Side:     side,
		Mode:     mode,
		Params:   base,
	}
}

// TestRenderIsDeterministicArgv: the argv is the config here, so two renders
// of one Spec must be byte-identical and must spell out the role, the
// websocket path and the header — and never the credential.
func TestRenderIsDeterministicArgv(t *testing.T) {
	a := Adapter{}
	for _, tc := range []struct {
		side tunnel.Side
		mode string
		role string
	}{
		{tunnel.SideA, tunnel.ModeRelay, "client"},
		{tunnel.SideB, tunnel.ModeRelay, "server"},
		{tunnel.SideA, tunnel.ModeReverse, "server"},
		{tunnel.SideB, tunnel.ModeReverse, "client"},
	} {
		spec := renderSpec(tc.side, tc.mode, map[string]string{paramHeader: testHeader})
		first, err := a.Render(spec)
		if err != nil {
			t.Fatalf("%s/%s: %v", tc.mode, tc.side, err)
		}
		second, err := a.Render(spec)
		if err != nil {
			t.Fatalf("%s/%s second render: %v", tc.mode, tc.side, err)
		}
		if first != second {
			t.Fatalf("%s/%s renders differ:\n%s\n---\n%s", tc.mode, tc.side, first, second)
		}

		var argv []string
		if err := json.Unmarshal([]byte(first), &argv); err != nil {
			t.Fatalf("%s/%s: Render must be a JSON argv: %v\n%s", tc.mode, tc.side, err, first)
		}
		if len(argv) < 2 || argv[0] != "chisel" || argv[1] != tc.role {
			t.Fatalf("%s/%s: want chisel %s, got %v", tc.mode, tc.side, tc.role, argv)
		}
		joined := strings.Join(argv, " ")
		// The websocket path and the extra header are client-side arguments:
		// the client writes the URL and --header, the server has no such flag
		// (verified against the pinned v1.12.0 --help). Asserting them on the
		// server argv would be asserting a flag chisel does not have.
		if tc.role == "client" {
			if !strings.Contains(joined, testPath) {
				t.Errorf("%s/%s: rendered argv does not carry the websocket path: %v", tc.mode, tc.side, argv)
			}
			if !strings.Contains(joined, testHeader) {
				t.Errorf("%s/%s: rendered argv does not carry the header: %v", tc.mode, tc.side, argv)
			}
		}
		// A credential belongs in the environment, never in the config.
		if strings.Contains(joined, "user:") || strings.Contains(joined, "--auth") {
			t.Errorf("%s/%s: rendered argv leaks an auth argument: %v", tc.mode, tc.side, argv)
		}
	}
}

// TestRenderRefusesWhatItCannotRun: a side missing the params it needs, a
// colliding publish port and a mode outside CONTRACT §2.0 are refusals, not
// a render that quietly drops the field.
func TestRenderRefusesWhatItCannotRun(t *testing.T) {
	a := Adapter{}

	noPeer := renderSpec(tunnel.SideA, tunnel.ModeRelay, nil)
	noPeer.Params = copyWithout(noPeer.Params, paramPeer)
	if _, err := a.Render(noPeer); err == nil || !strings.Contains(err.Error(), paramPeer) {
		t.Fatalf("side a without peer must be refused, got %v", err)
	}

	noTarget := renderSpec(tunnel.SideB, tunnel.ModeRelay, nil)
	noTarget.Params = copyWithout(noTarget.Params, paramTarget)
	if _, err := a.Render(noTarget); err == nil || !strings.Contains(err.Error(), paramTarget) {
		t.Fatalf("side b without target must be refused, got %v", err)
	}

	noPublish := renderSpec(tunnel.SideA, tunnel.ModeReverse, nil)
	noPublish.Params = copyWithout(noPublish.Params, paramPublishPort)
	if _, err := a.Render(noPublish); err == nil || !strings.Contains(err.Error(), paramPublishPort) {
		t.Fatalf("reverse side a without publish_port must be refused, got %v", err)
	}

	clash := renderSpec(tunnel.SideA, tunnel.ModeReverse,
		map[string]string{paramPublishPort: "18080"})
	if _, err := a.Render(clash); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("publish_port == listen_port must be refused, got %v", err)
	}

	badMode := renderSpec(tunnel.SideA, "smtp", nil)
	if _, err := a.Render(badMode); !errors.Is(err, tunnel.ErrInvalidSpec) {
		t.Fatalf("mode outside relay|reverse must be ErrInvalidSpec, got %v", err)
	}

	badPath := renderSpec(tunnel.SideA, tunnel.ModeRelay, map[string]string{paramPath: "no-slash"})
	if _, err := a.Render(badPath); err == nil || !strings.Contains(err.Error(), paramPath) {
		t.Fatalf("a path without a leading slash must be refused, got %v", err)
	}
}

func copyWithout(in map[string]string, drop string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k != drop {
			out[k] = v
		}
	}
	return out
}

// TestNoShell: chisel's configuration is a command line, so a param carrying
// shell metacharacters must arrive as one literal argument. If any of these
// ever reached a shell, `;`, `|`, backticks and $( ) would be operators
// instead of bytes — this is the security assertion, not a style one.
func TestNoShell(t *testing.T) {
	hostile := map[string]string{
		paramHeader: "X-A: b; echo pwned",
	}
	spec := renderSpec(tunnel.SideA, tunnel.ModeRelay, map[string]string{
		paramTarget: "127.0.0.1:1; touch /tmp/pg-pwned",
		paramPath:   "/p|ath`id`",
		paramHeader: hostile[paramHeader],
	})
	out, err := (Adapter{}).Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	var argv []string
	if err := json.Unmarshal([]byte(out), &argv); err != nil {
		t.Fatal(err)
	}
	// The destination never reaches chisel at all: side B's shim dials it from
	// our own process, so a hostile target cannot land in an argv, let alone a
	// shell. Path and header are the values chisel really receives.
	for _, arg := range argv {
		if strings.Contains(arg, "touch /tmp/pg-pwned") {
			t.Errorf("the target was handed to chisel: %v", argv)
		}
	}
	for _, want := range []string{"/p|ath`id`", hostile[paramHeader]} {
		found := false
		for _, arg := range argv {
			// Containment, not equality: the path rides *inside* the URL
			// element (http://host:port<path>), the header is its own element.
			// What must hold is that the value survived inside a single
			// argument instead of being re-tokenised.
			if arg == want || strings.Contains(arg, want) {
				found = true
			}
			for _, shell := range []string{"sh", "bash", "cmd", "powershell", "-c", "/c"} {
				if arg == shell {
					t.Errorf("argv names a shell: %v", argv)
				}
			}
			if strings.ContainsAny(arg, "\r\n") {
				t.Errorf("argv element contains a line break: %q", arg)
			}
		}
		if !found {
			t.Errorf("metacharacter value did not survive as one literal argument: %q not in %v", want, argv)
		}
	}

	// A peer that cannot be a host:port is rejected outright rather than
	// handed to something that might parse it loosely.
	badPeer := renderSpec(tunnel.SideA, tunnel.ModeRelay, map[string]string{paramPeer: "host:1; id"})
	if _, err := (Adapter{}).Render(badPeer); err == nil {
		t.Fatal("peer with a non-numeric port must be refused")
	}
}

// ------------------------------------------------------------------ start

// sink is a one-shot destination: records everything it is handed.
type sink struct {
	ln   net.Listener
	mu   sync.Mutex
	got  []byte
	want []byte
}

func newSink(t *testing.T) *sink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *sink) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.got = append(s.got, buf[:n]...)
	want := s.want
	s.mu.Unlock()
	_, _ = conn.Write(want)
}

func (s *sink) addr() string { return s.ln.Addr().String() }

func (s *sink) close() { _ = s.ln.Close() }

func (s *sink) received() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]byte, len(s.got))
	copy(out, s.got)
	return out
}

// TestWrongCredentialRefusesTunnel: side B serves with a credential side A
// does not have. The handshake must fail (an Error record naming it), the
// destination must receive nothing, and side A's ingress must not sit open
// pretending to be a tunnel.
func TestWrongCredentialRefusesTunnel(t *testing.T) {
	setBundle(t)
	t.Setenv(SecretAuth, "right:credential")

	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: t.TempDir()})
	t.Cleanup(m.Shutdown)
	alloc := tunnel.NewAllocator()

	sk := newSink(t)
	defer sk.close()
	sk.want = []byte("reply")

	portsA, portsB := alloc.AllocPair(), alloc.AllocPair()
	id := "wrongcred-" + strconv.FormatInt(time.Now().UnixNano()%1e9, 10)
	specA := tunnel.Spec{
		TunnelID: id, Tool: Tool, ToolVersion: Version, Side: tunnel.SideA,
		Mode: tunnel.ModeRelay,
		Params: map[string]string{
			tunnel.ParamListenPort: strconv.Itoa(portsA.Listen),
			paramListenHost:        "127.0.0.1",
			paramPath:              testPath,
			paramPeer:              fmt.Sprintf("127.0.0.1:%d", portsB.Listen),
			paramTarget:            sk.addr(),
		},
		Secrets: map[string]string{SecretAuth: ""}, Enabled: true,
	}
	specB := specA.Clone()
	specB.Side = tunnel.SideB
	specB.Params = map[string]string{
		tunnel.ParamListenPort: strconv.Itoa(portsB.Listen),
		paramListenHost:        "127.0.0.1",
		paramPath:              testPath,
		paramPeer:              fmt.Sprintf("127.0.0.1:%d", portsA.Listen),
		paramTarget:            sk.addr(),
	}
	specB.Secrets[SecretAuth] = "wrong:credential"

	if err := m.Start(context.Background(), specA, portsA); err != nil {
		t.Fatalf("start side a: %v", err)
	}
	if err := m.Start(context.Background(), specB, portsB); err != nil {
		t.Fatalf("start side b: %v", err)
	}
	defer func() { _ = m.Stop(id) }()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", portsA.Listen), 5*time.Second)
	if err != nil {
		t.Fatalf("dial side a's ingress: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	readErr := error(nil)
	for readErr == nil {
		if _, err := conn.Read(buf); err != nil {
			readErr = err
		}
	}
	if readErr == nil {
		t.Fatal("the tunnel answered instead of failing")
	}

	if got := len(sk.received()); got != 0 {
		t.Fatalf("wrong credential: %d byte(s) reached the destination", got)
	}
	// The refusal must be explicit and about the credential, not just "nothing
	// happened": chisel says "Login failed" / "Authentication failed".
	deadline := time.Now().Add(10 * time.Second)
	for {
		authFailure := false
		for _, rec := range m.Logs(id) {
			if rec.Level != "Error" {
				continue
			}
			lower := strings.ToLower(rec.Detail)
			if strings.Contains(lower, "login failed") || strings.Contains(lower, "authentication failed") {
				authFailure = true
			}
		}
		if authFailure {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no Error record names the failed credential; logs: %+v", m.Logs(id))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ------------------------------------------------------------------ binary

// TestBinaryPinEnforced is CONTRACT §2.1's install rule: the bundle's own
// bytes are used offline, and a chisel at the same path with different bytes
// is refused rather than run.
func TestBinaryPinEnforced(t *testing.T) {
	dir := setBundle(t)
	pin, ok := tunnel.PinFor(Tool)
	if !ok {
		t.Fatal("no pin registered for chisel")
	}
	asset, err := pin.AssetFor(tunnel.PlatformKey())
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := tunnel.ResolveBinary(Tool, dir)
	if err != nil {
		t.Fatalf("offline resolve: %v", err)
	}
	// filepath.Rel, not strings.HasPrefix: ResolveBinary returns Windows
	// separators while dir is whatever the test built, and a prefix comparison
	// across the two disagrees about every path on this OS.
	if rel, err := filepath.Rel(dir, resolved); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("resolved %q outside the offline bundle %q", resolved, dir)
	}
	sum, err := tunnel.FileSHA256(resolved)
	if err != nil {
		t.Fatal(err)
	}
	want := asset.BinSHA256
	if want == "" {
		want = asset.SHA256
	}
	if !strings.EqualFold(sum, want) {
		t.Fatalf("binary sha256 %s, pin wants %s", sum, want)
	}

	// Same path, different bytes: refused with ErrBinaryMismatch.
	fake := t.TempDir()
	fakeBin := filepath.Join(fake, filepath.FromSlash(asset.Bin))
	if err := os.MkdirAll(filepath.Dir(fakeBin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fakeBin, []byte("not chisel at all"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := tunnel.ResolveBinary(Tool, fake); !errors.Is(err, tunnel.ErrBinaryMismatch) {
		t.Fatalf("tampered bundle must be ErrBinaryMismatch, got %v", err)
	}
}

// ------------------------------------------------------ websocket path/headers

type seenRequest struct {
	path    string
	headers http.Header
}

// TestWebSocketPathAndHeaderReachTheWire points side A's client at a probe
// server instead of side B, and checks that the path and header Render put on
// the command line are the ones chisel puts on the wire.
//
// What chisel does *not* do is restrict the upgrade to one path — v1.12.0
// accepts a websocket on any path (verified by hand: sessions opened on
// /pg and /other alike), so the path is not access control. Enforcing one
// would need a shim in front of side B's listener, i.e. a third port: a
// change request, not something to paper over in a test.
func TestWebSocketPathAndHeaderReachTheWire(t *testing.T) {
	setBundle(t)
	t.Setenv(SecretAuth, "probe:credential")

	var mu sync.Mutex
	var seen *seenRequest
	probe := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = &seenRequest{path: r.URL.Path, headers: r.Header.Clone()}
		mu.Unlock()
		http.Error(w, "not a chisel endpoint", http.StatusTeapot)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	go func() { _ = probe.Serve(ln) }()

	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: t.TempDir()})
	t.Cleanup(m.Shutdown)
	alloc := tunnel.NewAllocator()

	ports := alloc.AllocPair()
	id := "pathprobe-1"
	spec := tunnel.Spec{
		TunnelID: id, Tool: Tool, ToolVersion: Version, Side: tunnel.SideA,
		Mode: tunnel.ModeRelay,
		Params: map[string]string{
			tunnel.ParamListenPort: strconv.Itoa(ports.Listen),
			paramListenHost:        "127.0.0.1",
			paramPath:              testPath,
			paramHeader:            testHeader,
			paramPeer:              ln.Addr().String(),
			paramTarget:            "127.0.0.1:1",
		},
		Secrets: map[string]string{SecretAuth: ""},
		Enabled: true,
	}
	if err := m.Start(context.Background(), spec, ports); err != nil {
		t.Fatalf("start side a: %v", err)
	}
	defer func() { _ = m.Stop(id) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		got := seen
		mu.Unlock()
		if got != nil {
			if got.path != testPath {
				t.Fatalf("client dialed path %q, rendered %q", got.path, testPath)
			}
			if h := got.headers.Get("X-PG-Test"); h != "chisel" {
				t.Fatalf("header X-PG-Test = %q, want %q (headers: %v)", h, "chisel", got.headers)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("chisel never sent its websocket request to the probe")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestPlainHttpRequestIsRefused: side B's listener answers a plain GET with
// 404 — a request that is not a websocket upgrade never reaches a tunnel.
func TestPlainHttpRequestIsRefused(t *testing.T) {
	setBundle(t)
	t.Setenv(SecretAuth, "server:credential")

	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: t.TempDir()})
	t.Cleanup(m.Shutdown)
	alloc := tunnel.NewAllocator()
	sk := newSink(t)

	ports := alloc.AllocPair()
	id := "plainreq-1"
	spec := tunnel.Spec{
		TunnelID: id, Tool: Tool, ToolVersion: Version, Side: tunnel.SideB,
		Mode: tunnel.ModeRelay,
		Params: map[string]string{
			tunnel.ParamListenPort: strconv.Itoa(ports.Listen),
			paramListenHost:        "127.0.0.1",
			paramPath:              testPath,
			paramPeer:              "127.0.0.1:" + strconv.Itoa(ports.Listen),
			paramTarget:            sk.addr(),
		},
		Secrets: map[string]string{SecretAuth: ""},
		Enabled: true,
	}
	if err := m.Start(context.Background(), spec, ports); err != nil {
		t.Fatalf("start side b: %v", err)
	}
	defer func() { _ = m.Stop(id) }()

	client := &http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{testPath, "/wrongpath"} {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d%s", ports.Listen, path))
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s: status %d, want 404 (path %q must not be an open endpoint)", path, resp.StatusCode, path)
		}
	}
}

// --------------------------------------------------------------- preflight

func TestPreflightNamesWhatIsMissing(t *testing.T) {
	setBundle(t)
	p := (Adapter{}).Preflight(context.Background(), tunnel.Spec{
		TunnelID: "pf-1", Tool: Tool, Side: tunnel.SideA, Mode: tunnel.ModeRelay,
	})
	if len(p) == 0 {
		t.Fatal("a spec with no params and no secret must report problems")
	}
	checks := map[string]string{}
	for _, problem := range p {
		checks[problem.Check] = problem.Detail
	}
	if detail, ok := checks["params"]; !ok || !strings.Contains(detail, paramPeer) {
		t.Fatalf("missing peer must be named, got %v", checks)
	}
	if _, ok := checks["secret"]; !ok {
		t.Fatalf("missing %s must be named, got %v", SecretAuth, checks)
	}

	ready := Adapter{}.Preflight(context.Background(), tunnel.Spec{
		TunnelID: "pf-2", Tool: Tool, Side: tunnel.SideA, Mode: tunnel.ModeRelay,
		Params: map[string]string{
			tunnel.ParamListenPort: "18080",
			paramPeer:              "127.0.0.1:18081",
			paramTarget:            "127.0.0.1:9",
		},
		Secrets: map[string]string{SecretAuth: ""},
	})
	if len(ready) != 0 {
		t.Fatalf("a complete relay side must be ready, got %+v", ready)
	}
}

// The credential must never travel on the command line: chisel reads AUTH
// from the environment, and any AUTH the node process itself carries is
// replaced rather than shadowed by a duplicate entry.
func TestAuthGoesThroughTheEnvironment(t *testing.T) {
	env := authEnv("user:pass")
	auth := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "AUTH=") {
			auth++
			if kv != "AUTH=user:pass" {
				t.Fatalf("AUTH = %q", kv)
			}
		}
	}
	if auth != 1 {
		t.Fatalf("want exactly one AUTH entry, got %d", auth)
	}
}
