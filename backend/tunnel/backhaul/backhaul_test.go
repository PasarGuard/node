package backhaul

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/backend/tunnel/tunneltest"
)

// adapter is the value under test; a package-level one keeps the composite
// literal out of if-statement initialisers, where Go wants parentheses.
var adapter = Adapter{}

// relaySpec is the shape the kit and the loopback tests build: both address
// params present (each side only reads its own), the secret declared by name
// so the Manager resolves it from the environment.
func relaySpec(id string, side tunnel.Side, mode string) tunnel.Spec {
	return tunnel.Spec{
		TunnelID:    id,
		Tool:        Tool,
		ToolVersion: Version,
		Side:        side,
		Mode:        mode,
		Params: map[string]string{
			paramListenHost: "127.0.0.1",
			paramTarget:     "127.0.0.1:9999",
			paramPeer:       "127.0.0.1:9998",
		},
		Secrets: map[string]string{SecretToken: ""},
		Enabled: true,
	}
}

// ---------------------------------------------------------------------------
// 1. The four-part testkit: traffic, restart, negative control, logs — on the
//    pinned binary, through loopback, zero skips on a host that can run it.

func TestFourPartRelay(t *testing.T) {
	requireBundle(t)
	t.Setenv(SecretToken, "four-part-secret")

	alloc := tunnel.NewAllocator()
	tunneltest.Run(t, tunneltest.Kit{
		Adapter: adapter,
		NewSpec: func(e tunneltest.Endpoints) tunnel.Spec {
			spec := relaySpec(e.TunnelID, e.Side, e.Mode)
			spec.Params[paramTarget] = e.Target
			spec.Params[paramPeer] = e.Peer
			return spec
		},
		Allocate: func() tunnel.Ports { return alloc.AllocPair() },
		// Side b's token is wrong: side a must reject it, nothing may reach
		// the destination, and the refusal must be explicit — not a tunnel
		// that quietly swallows its bytes.
		Corrupt: func(s *tunnel.Spec) {
			if s.Secrets == nil {
				s.Secrets = map[string]string{}
			}
			s.Secrets[SecretToken] = "deliberately-wrong-token"
		},
	})
}

// ---------------------------------------------------------------------------
// 2. reverse mode. The kit only builds relay endpoints (tunneltest.endpoints
//    hard-codes ModeRelay), so reverse gets its own loopback run: side a
//    publishes a port, side b — the far side, behind NAT in a real deployment
//    — delivers to a service listening here (CONTRACT §2.0).

func TestReverseLoopback(t *testing.T) {
	requireBundle(t)
	t.Setenv(SecretToken, "reverse-secret")

	alloc := tunnel.NewAllocator()
	portsA, portsB := alloc.AllocPair(), alloc.AllocPair()
	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: t.TempDir()})
	t.Cleanup(m.Shutdown)

	service, stop := echoServer(t)
	defer stop()

	const id = "backhaul-reverse-1"
	specA := relaySpec(id, tunnel.SideA, tunnel.ModeReverse)
	specA.Params[paramTarget] = service
	specB := relaySpec(id, tunnel.SideB, tunnel.ModeReverse)
	specB.Params[paramPeer] = fmt.Sprintf("127.0.0.1:%d", portsA.Listen)

	// The kit proves render determinism for relay; reverse is asserted here.
	assertRenderDeterministic(t, specA)
	assertRenderDeterministic(t, specB)

	ctx := context.Background()
	if err := m.Start(ctx, specA, portsA); err != nil {
		t.Fatalf("start side a (reverse): %v", err)
	}
	if err := m.Start(ctx, specB, portsB); err != nil {
		t.Fatalf("start side b (reverse): %v", err)
	}

	// Bytes enter at a's published port and must come back from the service.
	payload := randomBytes(4096)
	got := dialRoundTrip(t, fmt.Sprintf("127.0.0.1:%d", portsA.Listen), payload)
	if string(got) != string(payload) {
		t.Fatalf("reverse tunnel echoed %d bytes, first difference at %d", len(got), firstDiff(got, payload))
	}
	waitForBothSidesCounting(t, m)

	if err := m.Stop(id); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 3. Render: deterministic, mode-typed, and strict about its parameters.

func TestRenderIsDeterministicForBothSides(t *testing.T) {
	for _, tc := range []struct{ side tunnel.Side; mode, want string }{
		{tunnel.SideA, tunnel.ModeRelay, "mode=relay"},
		{tunnel.SideB, tunnel.ModeRelay, "mode=relay"},
		{tunnel.SideA, tunnel.ModeReverse, "mode=reverse"},
		{tunnel.SideB, tunnel.ModeReverse, "mode=reverse"},
		{tunnel.SideA, "", "mode=relay"}, // the documented default
	} {
		spec := relaySpec("render-1", tc.side, tc.mode)
		first, err := adapter.Render(spec)
		if err != nil {
			t.Fatalf("side %s mode %q: %v", tc.side, tc.mode, err)
		}
		second, err := adapter.Render(spec)
		if err != nil {
			t.Fatal(err)
		}
		if first != second {
			t.Fatalf("side %s mode %q is not deterministic:\n%s\n---\n%s", tc.side, tc.mode, first, second)
		}
		if !strings.Contains(first, tc.want) {
			t.Fatalf("render must record %q:\n%s", tc.want, first)
		}
		wantSection := "[server]"
		if tc.side == tunnel.SideB {
			wantSection = "[client]"
		}
		if !strings.Contains(first, wantSection) {
			t.Fatalf("side %s must render a %s section:\n%s", tc.side, wantSection, first)
		}
	}
}

func TestRenderRefusesAnUnknownMode(t *testing.T) {
	spec := relaySpec("mode-1", tunnel.SideA, "smtp")
	_, err := adapter.Render(spec)
	if err == nil {
		t.Fatal("Render accepted a mode that is neither relay nor reverse")
	}
	// The framework's own validator speaks first (ErrInvalidSpec); a mode the
	// adapter itself does not implement is ErrModeUnsupported, asserted on
	// the resolver the Render path runs.
	if !strings.Contains(err.Error(), "smtp") {
		t.Fatalf("the refusal must name the mode, got: %v", err)
	}
	if _, err := resolveMode("smtp"); !errors.Is(err, tunnel.ErrModeUnsupported) {
		t.Fatalf("resolveMode must refuse an unimplemented mode with ErrModeUnsupported, got %v", err)
	}
	for _, mode := range []string{tunnel.ModeRelay, tunnel.ModeReverse} {
		if _, err := resolveMode(mode); err != nil {
			t.Fatalf("mode %q must be implemented: %v", mode, err)
		}
	}
}

func TestRenderRejectsUnknownParamsNamingTheKey(t *testing.T) {
	spec := relaySpec("param-1", tunnel.SideA, tunnel.ModeRelay)
	spec.Params["bandwith"] = "10mbit" // a typo that would otherwise be dropped
	_, err := adapter.Render(spec)
	if err == nil {
		t.Fatal("an unknown params key was accepted")
	}
	if !strings.Contains(err.Error(), "bandwith") {
		t.Fatalf("the refusal must name the key, got: %v", err)
	}
	if !errors.Is(err, tunnel.ErrInvalidSpec) {
		t.Fatalf("an unknown key is a spec problem, got %v", err)
	}
}

func TestRenderRejectsValuesOutsideTheirVocabulary(t *testing.T) {
	for _, tc := range []struct {
		side  tunnel.Side
		key   string
		value string
	}{
		{tunnel.SideA, paramTransport, "carrier-pigeon"},
		{tunnel.SideB, paramTransport, "wss"}, // needs TLS material this adapter does not own
		{tunnel.SideA, paramLogLevel, "loud"},
		{tunnel.SideA, paramSkipOptz, "maybe"},
		{tunnel.SideA, paramTarget, "no-port-here"},
		{tunnel.SideB, paramPeer, "127.0.0.1"},
		{tunnel.SideA, paramListenHost, `127.0.0.1"; evil = true`},
	} {
		spec := relaySpec("value-1", tc.side, tunnel.ModeRelay)
		spec.Params[tc.key] = tc.value
		_, err := adapter.Render(spec)
		if err == nil {
			t.Fatalf("params.%s=%q was accepted", tc.key, tc.value)
		}
		if !strings.Contains(err.Error(), tc.key) {
			t.Fatalf("params.%s=%q: refusal must name the key, got: %v", tc.key, tc.value, err)
		}
	}
}

func TestEachSideIsRefusedWithoutItsAddress(t *testing.T) {
	a := relaySpec("req-a", tunnel.SideA, tunnel.ModeRelay)
	delete(a.Params, paramTarget)
	if _, err := adapter.Render(a); err == nil || !strings.Contains(err.Error(), paramTarget) {
		t.Fatalf("side a without %s: want an error naming it, got %v", paramTarget, err)
	}

	b := relaySpec("req-b", tunnel.SideB, tunnel.ModeRelay)
	delete(b.Params, paramPeer)
	if _, err := adapter.Render(b); err == nil || !strings.Contains(err.Error(), paramPeer) {
		t.Fatalf("side b without %s: want an error naming it, got %v", paramPeer, err)
	}
}

// The token is the one value in the config that is not checked against a
// vocabulary — it comes from the environment — so it is escaped rather than
// trusted. A quote in a token must not become a second TOML key.
func TestRenderEscapesTheToken(t *testing.T) {
	spec := relaySpec("tok-1", tunnel.SideA, tunnel.ModeRelay)
	spec.Secrets[SecretToken] = `pa"ss\word`
	out, err := adapter.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `token = "pa\"ss\\word"`) {
		t.Fatalf("token is not TOML-escaped:\n%s", out)
	}
}

// Start refuses to bring up a tunnel it cannot authenticate: an undeclared
// secret is a tunnel anyone who reaches the transport could ride.
func TestStartRefusesAMissingToken(t *testing.T) {
	spec := relaySpec("no-token", tunnel.SideA, tunnel.ModeRelay)
	spec.Secrets = nil
	spec.Params[tunnel.ParamConfigDir] = t.TempDir()
	_, err := adapter.Start(context.Background(), spec, tunnel.Ports{Listen: 41001, Control: 41002})
	if !errors.Is(err, tunnel.ErrSecretUnresolved) || !strings.Contains(err.Error(), SecretToken) {
		t.Fatalf("want an ErrSecretUnresolved naming %s, got %v", SecretToken, err)
	}
}

func TestStartRefusesAPortPairThatIsNotAPair(t *testing.T) {
	spec := relaySpec("bad-pair", tunnel.SideA, tunnel.ModeRelay)
	spec.Secrets[SecretToken] = "x"
	spec.Params[tunnel.ParamConfigDir] = t.TempDir()
	// Side b derives side a's transport as peer+1, so a Ports that breaks
	// Control == Listen+1 would silently point at the wrong port.
	_, err := adapter.Start(context.Background(), spec, tunnel.Ports{Listen: 41011, Control: 41099})
	if !errors.Is(err, tunnel.ErrInvalidSpec) || !strings.Contains(err.Error(), "Listen+1") {
		t.Fatalf("want a refusal naming the Control == Listen+1 rule, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// 4. Windows: no asset exists, and the adapter says so instead of failing
//    later with something an operator cannot act on.

func TestWindowsIsUnpinnedAndRefused(t *testing.T) {
	pin, ok := tunnel.PinFor(Tool)
	if !ok {
		t.Fatal("pins.json is not registered")
	}
	// The fact behind the refusal, asserted on every host: upstream ships
	// linux builds only, so pins.json must not claim a windows asset.
	if asset, err := pin.AssetFor("windows-amd64"); err == nil {
		t.Fatalf("pins.json claims a Windows asset (%s) that Musixal/Backhaul does not publish", asset.Name)
	}
	if !strings.Contains(errNoWindows().Error(), "no Windows asset") {
		t.Fatalf("the platform refusal must say exactly why: %v", errNoWindows())
	}

	if runtime.GOOS != "windows" {
		// The runtime half of the assertion needs a Windows host; it runs
		// there (this suite's local gate) rather than being faked here.
		return
	}

	spec := relaySpec("win-1", tunnel.SideA, tunnel.ModeRelay)
	spec.Secrets[SecretToken] = "x"
	spec.Params[tunnel.ParamConfigDir] = t.TempDir()
	_, err := adapter.Start(context.Background(), spec, tunnel.Ports{Listen: 41021, Control: 41022})
	if !errors.Is(err, tunnel.ErrBinaryNotFound) || !strings.Contains(err.Error(), "no Windows asset") {
		t.Fatalf("Start on Windows: want a refusal naming the missing asset, got %v", err)
	}

	problems := adapter.Preflight(context.Background(), spec)
	if len(problems) == 0 {
		t.Fatal("Preflight reported no problem on a host that cannot run backhaul")
	}
	if problems[0].Check != "platform" || !strings.Contains(problems[0].Detail, "Windows") {
		t.Fatalf("Preflight must lead with the platform problem, got %+v", problems[0])
	}
}

// ---------------------------------------------------------------------------
// 5. The pin: a binary that is not the pinned one never runs, and the bundle
//    is resolved from disk alone.

func TestWrongBinaryHashIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("backhaul has no windows-amd64 asset, so there is no pin hash for this host to check against")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "backhaul"), []byte("not the pinned build"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := tunnel.ResolveBinary(Tool, dir)
	if !errors.Is(err, tunnel.ErrBinaryMismatch) {
		t.Fatalf("a wrong build must be refused with ErrBinaryMismatch, got %v", err)
	}
}

// The bundle is a directory on disk; nothing here fetches. That is the whole
// point of CONTRACT §2.1's install rule — a node with no network still starts.
func TestOfflineBundleResolvesWithoutNetwork(t *testing.T) {
	requireBundle(t)
	dir := os.Getenv("TUNNEL_BUNDLE_DIR")
	bin, err := tunnel.ResolveBinary(Tool, dir)
	if err != nil {
		t.Fatalf("resolve from %s: %v", dir, err)
	}
	if !strings.HasPrefix(bin, dir) {
		t.Fatalf("resolved %s outside the bundle directory %s", bin, dir)
	}
	sum, err := tunnel.FileSHA256(bin)
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := tunnel.PinFor(Tool)
	asset, err := pin.AssetFor(tunnel.PlatformKey())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(sum, asset.BinSHA256) {
		t.Fatalf("binary is %s, pin says %s", sum, asset.BinSHA256)
	}
}

// ---------------------------------------------------------------------------
// helpers

// requireBundle points TUNNEL_BUNDLE_DIR at the pinned binary, extracting the
// pinned archive when the bundle only has that (which is how the fetcher lays
// it down). It skips — never passes silently — with the reason stated: a host
// that cannot produce the binary has no four-part run to report, and upstream
// publishes nothing for Windows at all.
func requireBundle(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("backhaul ships no Windows asset (Musixal/Backhaul " + Version +
			" publishes linux builds only), so the run-the-binary test runs on a Linux node")
	}
	var dirs []string
	if d := os.Getenv("TUNNEL_BUNDLE_DIR"); d != "" {
		dirs = append(dirs, d)
	}
	dirs = append(dirs, "/opt/tunnel-bundle")

	pin, ok := tunnel.PinFor(Tool)
	if !ok {
		t.Fatal("pins.json is not registered")
	}
	asset, err := pin.AssetFor(tunnel.PlatformKey())
	if err != nil {
		t.Fatalf("no pin for this platform: %v", err)
	}

	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(d, "backhaul")); err != nil {
			continue
		}
		t.Setenv("TUNNEL_BUNDLE_DIR", d)
		bin, err := tunnel.ResolveBinary(Tool, d)
		if err != nil {
			t.Fatalf("bundle %s: %v", d, err)
		}
		// Named in the test log: the four-part run is only worth something
		// when it is clear which pinned binary it executed.
		t.Logf("bundle %s -> %s (sha256 verified against pins.json)", d, bin)
		return
	}
	for _, d := range dirs {
		archive := filepath.Join(d, asset.Name)
		if _, err := os.Stat(archive); err != nil {
			continue
		}
		dir := extractArchive(t, archive, asset)
		t.Setenv("TUNNEL_BUNDLE_DIR", dir)
		bin, err := tunnel.ResolveBinary(Tool, dir)
		if err != nil {
			t.Fatalf("extracted %s: %v", archive, err)
		}
		t.Logf("extracted %s -> %s (archive and binary sha256 verified against pins.json)", archive, bin)
		return
	}
	t.Skipf("no backhaul binary on this host: set TUNNEL_BUNDLE_DIR to a directory holding %q or the pinned archive %s (looked in: %s)",
		"backhaul", asset.Name, strings.Join(dirs, ", "))
}

// extractArchive unpacks the pinned tarball into a temp dir and leaves the
// executable at <dir>/backhaul, which is where ResolveBinary looks. The
// archive hash is checked first and the binary hash by ResolveBinary, so the
// extraction cannot smuggle in a different build.
func extractArchive(t *testing.T, archive string, asset tunnel.PinAsset) string {
	t.Helper()
	sum, err := tunnel.FileSHA256(archive)
	if err != nil {
		t.Fatalf("hash %s: %v", archive, err)
	}
	if !strings.EqualFold(sum, asset.SHA256) {
		t.Fatalf("%s is %s, pin wants %s", archive, sum, asset.SHA256)
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()

	dir := t.TempDir()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read %s: %v", archive, err)
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != asset.Bin {
			continue
		}
		out := filepath.Join(dir, asset.Bin)
		w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, tr); err != nil {
			w.Close()
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	t.Fatalf("%s contains no %s", archive, asset.Bin)
	return ""
}

// echoServer is the service behind side b in the reverse test: it writes back
// exactly what it is sent, so a byte that arrives out of order or not at all
// is visible.
func echoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

func dialRoundTrip(t *testing.T, addr string, payload []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	return got
}

func waitForBothSidesCounting(t *testing.T, m *tunnel.Manager) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		bad := ""
		for _, st := range m.List() {
			if st.BytesUp == 0 || st.BytesDown == 0 {
				bad = fmt.Sprintf("%s side %s: up=%d down=%d — both directions must be counted",
					st.TunnelID, st.Side, st.BytesUp, st.BytesDown)
			}
		}
		if bad == "" {
			if len(m.List()) == 0 {
				t.Fatal("no side is running")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(bad)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func assertRenderDeterministic(t *testing.T, spec tunnel.Spec) {
	t.Helper()
	first, err := adapter.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := adapter.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("Render is not deterministic for %s side %s:\n%s\n---\n%s", spec.TunnelID, spec.Side, first, second)
	}
}

func randomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return buf
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
