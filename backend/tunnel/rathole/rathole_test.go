package rathole

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/backend/tunnel/tunneltest"
)

// TestFourPartReverse is rathole's run of the four-part kit: render
// determinism, traffic through loopback, restart from the same Spec, a
// corrupted token refused, and log records addressable by tunnel_id — four
// steps, zero skips.
//
// The Spec carries mode=reverse, not the kit's Endpoints.Mode: the kit labels
// its own topology "relay", but rathole's control plane runs the other way —
// side b dials side a — which is exactly what CONTRACT §2.0 calls reverse.
// Reporting relay here would claim a forward path rathole does not have.
func TestFourPartReverse(t *testing.T) {
	setBundle(t)
	t.Setenv(SecretToken, "four-part-secret")
	// Nothing may be fetched at run time: the only mirror a downloader could
	// use points at a closed port, so the bundle is proven to be offline.
	t.Setenv("TUNNEL_GITHUB_MIRROR", "http://127.0.0.1:9")

	alloc := tunnel.NewAllocator()
	tunneltest.Run(t, tunneltest.Kit{
		Adapter: Adapter{},
		NewSpec: func(e tunneltest.Endpoints) tunnel.Spec {
			spec := tunnel.Spec{
				TunnelID:    e.TunnelID,
				Tool:        Tool,
				ToolVersion: Version,
				Side:        e.Side,
				Mode:        tunnel.ModeReverse,
				Params:      map[string]string{paramListenHost: "127.0.0.1"},
				Secrets:     map[string]string{SecretToken: ""},
				Enabled:     true,
			}
			if e.Side == tunnel.SideB {
				// Side a's control port is its listen port + 1 (CONTRACT's
				// pair rule); the panel writes the same number as remote_addr.
				control, err := peerControlAddr(e.Peer)
				if err != nil {
					t.Fatalf("peer control for %q: %v", e.Peer, err)
				}
				spec.Params[paramRemoteAddr] = control
				spec.Params[paramTarget] = e.Target
			}
			return spec
		},
		Allocate: func() tunnel.Ports { return alloc.AllocPair() },
		Corrupt: func(s *tunnel.Spec) {
			if s.Secrets == nil {
				s.Secrets = map[string]string{}
			}
			s.Secrets[SecretToken] = "deliberately-wrong-token"
		},
	})
}

// TestWrongTokenIsRefused is the headline case: rathole's token is the whole
// auth story, so a wrong one must refuse the side outright (not leave it
// "running"), nothing may be published, and the server must say so at Error
// level. Both the refused state and the log line are asserted.
func TestWrongTokenIsRefused(t *testing.T) {
	setBundle(t)
	t.Setenv(SecretToken, "correct-token")

	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: t.TempDir()})
	t.Cleanup(m.Shutdown)
	alloc := tunnel.NewAllocator()
	portsA, portsB := alloc.AllocPair(), alloc.AllocPair()

	const id = "rathole-token-mismatch"
	specA := baseSpec(id, tunnel.SideA)
	specB := baseSpec(id, tunnel.SideB)
	specB.Params[paramRemoteAddr] = fmt.Sprintf("127.0.0.1:%d", portsA.Control)
	specB.Params[paramTarget] = "127.0.0.1:1" // nothing listens: nothing must arrive
	// A value planted here is a value ResolveFromEnv keeps — the same way the
	// kit plants its corruption.
	specB.Secrets[SecretToken] = "wrong-token-value"

	if err := m.Start(context.Background(), specA, portsA); err != nil {
		t.Fatalf("start side a: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(id) })

	startErr := m.Start(context.Background(), specB, portsB)
	if startErr == nil {
		t.Fatal("side b started with a wrong token — a refusal was expected")
	}
	if !strings.Contains(strings.ToLower(startErr.Error()), "authentication") {
		t.Fatalf("the refusal must name the authentication, got: %v", startErr)
	}
	for _, st := range m.List() {
		if st.Side == "b" {
			t.Fatalf("a refused side must not be registered as running: %+v", st)
		}
	}

	// The published side answers, and delivers nothing at all.
	ingress := fmt.Sprintf("127.0.0.1:%d", portsA.Listen)
	conn, err := net.DialTimeout("tcp", ingress, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the published side %s: %v", ingress, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(make([]byte, 64)); err != nil {
		t.Fatalf("write to the published side: %v", err)
	}
	buf := make([]byte, 64)
	n, readErr := conn.Read(buf)
	if readErr == nil {
		t.Fatalf("a wrong token still delivered %d byte(s)", n)
	}

	// The refusal is also explicit in the server's own log.
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, rec := range m.Logs(id) {
			if rec.Level == "Error" && strings.Contains(strings.ToLower(rec.Detail), "authentication") {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no Error-level authentication record for tunnel %s: %+v", id, m.Logs(id))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestRenderIsDeterministicAndRefusesRelay covers the two Render obligations:
// byte-identical output for one Spec (which is what makes the kit's restart
// step mean anything), and an explicit refusal of a mode with no passing
// loopback run (CONTRACT §2.0) at Render *and* at Start.
func TestRenderIsDeterministicAndRefusesRelay(t *testing.T) {
	setBundle(t)
	spec := baseSpec("render-1", tunnel.SideA)
	spec.Params[tunnel.ParamListenPort] = "23123"

	first, err := Adapter{}.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Adapter{}.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("renders differ:\n%s\n---\n%s", first, second)
	}
	for _, want := range []string{"[server]", "bind_addr", "23124", "[::1]:23123", "mode=reverse"} {
		if !strings.Contains(first, want) {
			t.Fatalf("server render is missing %q:\n%s", want, first)
		}
	}

	spec.Mode = tunnel.ModeRelay
	adapter := Adapter{}
	if _, err := adapter.Render(spec); !errors.Is(err, tunnel.ErrModeUnsupported) {
		t.Fatalf("relay must be refused by Render, got %v", err)
	}
	spec.Params[tunnel.ParamConfigDir] = t.TempDir()
	if _, err := adapter.Start(context.Background(), spec, tunnel.Ports{Listen: 23123, Control: 23124}); !errors.Is(err, tunnel.ErrModeUnsupported) {
		t.Fatalf("a caller that skips Render must get the same refusal, got %v", err)
	}
}

// TestStrictConfigValidation: rathole's schema is strict about which block a
// key lives in, so an unknown or misplaced key must fail Render naming it —
// never become a config rathole starts and silently ignores.
func TestStrictConfigValidation(t *testing.T) {
	setBundle(t)
	sideA := baseSpec("strict-a", tunnel.SideA)
	sideB := baseSpec("strict-b", tunnel.SideB)
	sideB.Params[paramRemoteAddr] = "127.0.0.1:2333"
	sideB.Params[paramTarget] = "127.0.0.1:80"

	cases := []struct {
		name string
		spec tunnel.Spec
		mut  func(*tunnel.Spec)
		want string
	}{
		{"unknown key", sideA, func(s *tunnel.Spec) { s.Params["proto"] = "udp" }, "proto"},
		{"missing remote_addr", sideA, func(s *tunnel.Spec) { s.Side = tunnel.SideB }, paramRemoteAddr},
		{"service name is not a bare key", sideA, func(s *tunnel.Spec) { s.Params[paramService] = "my.service" }, paramService},
		{"listen port is not a number", sideA, func(s *tunnel.Spec) { s.Params[tunnel.ParamListenPort] = "abc" }, tunnel.ParamListenPort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := tc.spec.Clone()
			tc.mut(&spec)
			_, err := Adapter{}.Render(spec)
			if err == nil {
				t.Fatalf("Render accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error must name %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestSharedParamsMapIsAcceptedOnBothSides: the panel sends ONE params map to
// both sides (TunnelSpec), so side A inevitably carries `target`/`remote_addr`
// — the keys side B needs to render. Refusing them made rathole the one tool
// that could never be started from the panel. Keys no side declares are still
// refused by name (that is the typo check), and side B's own requirements are
// unchanged.
func TestSharedParamsMapIsAcceptedOnBothSides(t *testing.T) {
	setBundle(t)
	shared := map[string]string{
		paramListenHost: "127.0.0.1",
		paramRemoteAddr: "127.0.0.1:23101",
		paramTarget:     "127.0.0.1:80",
	}

	adapter := Adapter{}
	sideA := baseSpec("shared-a", tunnel.SideA)
	for k, v := range shared {
		sideA.Params[k] = v
	}
	if _, err := adapter.Render(sideA); err != nil {
		t.Fatalf("side a refused the shared params map: %v", err)
	}

	sideB := baseSpec("shared-b", tunnel.SideB)
	for k, v := range shared {
		sideB.Params[k] = v
	}
	if _, err := adapter.Render(sideB); err != nil {
		t.Fatalf("side b refused the shared params map: %v", err)
	}

	// The typo check survives: a key no side owns is still an error.
	sideA.Params["proto"] = "udp"
	if _, err := adapter.Render(sideA); err == nil || !strings.Contains(err.Error(), "proto") {
		t.Fatalf("an undeclared key must still be refused naming it, got %v", err)
	}
}

// TestBothSidesRender: side a is rathole's server, side b its client, and the
// two configs are not interchangeable.
func TestBothSidesRender(t *testing.T) {
	server, err := Adapter{}.Render(sideSpec(tunnel.SideA, "23100"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := Adapter{}.Render(sideSpec(tunnel.SideB, "23200"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(server, "[server]") || strings.Contains(server, "[client]") {
		t.Fatalf("side a must render a server config:\n%s", server)
	}
	if !strings.Contains(client, "[client]") || strings.Contains(client, "[server]") {
		t.Fatalf("side b must render a client config:\n%s", client)
	}
	if !strings.Contains(client, `remote_addr = "127.0.0.1:23101"`) {
		t.Fatalf("side b must dial side a's control port (listen+1):\n%s", client)
	}
	if !strings.Contains(client, `local_addr = "127.0.0.1:23200"`) {
		t.Fatalf("side b must deliver through its own tap:\n%s", client)
	}
	// The token travels on the config because rathole reads it from there;
	// it must never travel on Params (CONTRACT §2.1).
	spec := sideSpec(tunnel.SideA, "23100")
	spec.Secrets = map[string]string{SecretToken: "super-secret-token"}
	cfg, err := Adapter{}.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, `default_token = "super-secret-token"`) {
		t.Fatalf("rathole reads its token from the config, so Render must write it:\n%s", cfg)
	}
	for _, k := range tunnel.SortedParams(spec.Params) {
		if spec.Params[k] == "super-secret-token" {
			t.Fatalf("the secret value leaked into Params[%s]", k)
		}
	}
}

// TestBinaryPinIsEnforced: a binary whose sha256 is not the pin's is refused
// by the resolver and by Start itself, and the verified bundle works with no
// network at all (the mirror this test installs points at a closed port).
func TestBinaryPinIsEnforced(t *testing.T) {
	dir := setBundle(t)
	t.Setenv("TUNNEL_GITHUB_MIRROR", "http://127.0.0.1:9")

	good, err := tunnel.ResolveBinary(Tool, dir)
	if err != nil {
		t.Fatalf("the offline bundle must resolve: %v", err)
	}

	// A bundle that holds the wrong bytes for the same file name.
	tampered := t.TempDir()
	data, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xff
	bad := filepath.Join(tampered, filepath.Base(good))
	if err := os.WriteFile(bad, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := tunnel.ResolveBinary(Tool, tampered); !errors.Is(err, tunnel.ErrBinaryMismatch) {
		t.Fatalf("a tampered bundle must be refused with ErrBinaryMismatch, got %v", err)
	}

	// Start refuses it too, even when the path arrives pre-resolved.
	spec := sideSpec(tunnel.SideB, "23300")
	spec.Params[tunnel.ParamBinaryPath] = bad
	spec.Params[tunnel.ParamConfigDir] = t.TempDir()
	_, err = Adapter{}.Start(context.Background(), spec, tunnel.Ports{Listen: 23300, Control: 23301})
	if !errors.Is(err, tunnel.ErrBinaryMismatch) {
		t.Fatalf("Start must refuse a binary that is not the pin, got %v", err)
	}
}

// TestPreflightReportsWhatThisHostCannotDo: an untested mode, a spec with a
// missing param and a missing binary are all Problems, and a valid reverse
// side on this host is empty (ready).
func TestPreflightReportsWhatThisHostCannotDo(t *testing.T) {
	setBundle(t)

	relay := sideSpec(tunnel.SideA, "23400")
	relay.Mode = tunnel.ModeRelay
	problems := Adapter{}.Preflight(context.Background(), relay)
	if len(problems) == 0 {
		t.Fatal("Preflight reported no problem for mode=relay, which has no passing run")
	}
	if problems[0].Check != "mode" {
		t.Fatalf("problem check = %q, want mode", problems[0].Check)
	}

	missing := sideSpec(tunnel.SideB, "23401")
	missing.Params = map[string]string{}
	problems = Adapter{}.Preflight(context.Background(), missing)
	if len(problems) == 0 || problems[0].Check != "params" {
		t.Fatalf("side b without remote_addr/target must be a params problem, got %+v", problems)
	}

	adapter := Adapter{}
	if got := adapter.Preflight(context.Background(), sideSpec(tunnel.SideA, "23402")); len(got) != 0 {
		t.Fatalf("a valid reverse side should be ready, got %+v", got)
	}
}

// ---------------------------------------------------------------- helpers

func sideSpec(side tunnel.Side, listen string) tunnel.Spec {
	spec := baseSpec("rathole-fixture", side)
	spec.Params[tunnel.ParamListenPort] = listen
	spec.Params[paramListenHost] = "127.0.0.1"
	if side == tunnel.SideB {
		spec.Params[paramRemoteAddr] = "127.0.0.1:23101"
		spec.Params[paramTarget] = "127.0.0.1:8080"
	}
	return spec
}

func baseSpec(id string, side tunnel.Side) tunnel.Spec {
	return tunnel.Spec{
		TunnelID:    id,
		Tool:        Tool,
		ToolVersion: Version,
		Side:        side,
		Mode:        tunnel.ModeReverse,
		Params:      map[string]string{},
		Secrets:     map[string]string{SecretToken: ""},
		Enabled:     true,
	}
}

// peerControlAddr turns the peer's listen address into its control address:
// control is always listen+1 (CONTRACT's pair rule), and that is the number
// the panel writes into the other side's remote_addr.
func peerControlAddr(peer string) (string, error) {
	host, port, err := net.SplitHostPort(peer)
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(n+1)), nil
}

func binaryName() string {
	if runtime.GOOS == "windows" {
		return "rathole.exe"
	}
	return "rathole"
}

// setBundle points TUNNEL_BUNDLE_DIR at a directory holding the pinned,
// extracted binary — the bundle's win/ or linux/ directory when it has one,
// or the platform's verified archive unpacked into a temp dir. It fails
// (never skips) when this machine has neither: a run without the binary would
// prove nothing.
func setBundle(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("TUNNEL_BUNDLE_DIR"); dir != "" {
		if _, err := os.Stat(filepath.Join(dir, binaryName())); err == nil {
			return dir
		}
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	// A node worktree lives in tools/<name>, the bundle in tools/tunnel-bundle;
	// the main checkout keeps both under the repository root.
	dirs := []string{
		filepath.Join(root, "..", "tunnel-bundle", bundleSubdir()),
		filepath.Join(root, "tools", "tunnel-bundle", bundleSubdir()),
	}
	for _, dir := range dirs {
		if _, err := os.Stat(filepath.Join(dir, binaryName())); err == nil {
			t.Setenv("TUNNEL_BUNDLE_DIR", dir)
			return dir
		}
	}
	archives := []string{
		filepath.Join(root, "..", "tunnel-bundle", assetName(t)),
		filepath.Join(root, "tools", "tunnel-bundle", assetName(t)),
	}
	for _, archive := range archives {
		if _, err := os.Stat(archive); err != nil {
			continue
		}
		out := t.TempDir()
		if err := extractBinary(archive, out); err != nil {
			t.Fatalf("extract %s: %v", archive, err)
		}
		t.Setenv("TUNNEL_BUNDLE_DIR", out)
		return out
	}
	t.Fatalf("pinned rathole not found: no %s in %v and no archive in %v; set TUNNEL_BUNDLE_DIR",
		binaryName(), dirs, archives)
	return ""
}

// assetName is this platform's archive name from the registered pin.
func assetName(t *testing.T) string {
	t.Helper()
	pin, ok := tunnel.PinFor(Tool)
	if !ok {
		t.Fatalf("no pin registered for %s", Tool)
	}
	asset, err := pin.AssetFor(tunnel.PlatformKey())
	if err != nil {
		t.Fatal(err)
	}
	return asset.Name
}

// extractBinary unpacks the pinned archive's executable into dir. The pin's
// sha256 covers the archive, and ResolveBinary re-checks the binary's own hash
// before anything runs, so an unpack here cannot smuggle in other bytes.
func extractBinary(archive, dir string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if filepath.Base(f.Name) != binaryName() || f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(filepath.Join(dir, binaryName()), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			_ = rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		_ = rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		return err
	}
	return fmt.Errorf("%s holds no %s", archive, binaryName())
}

func bundleSubdir() string {
	if runtime.GOOS == "windows" {
		return "win"
	}
	return "linux"
}
