package frp

import (
	"context"
	"errors"
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

// ---------------------------------------------------------------------------
// the four-part kit, twice: once per mode this adapter declares.

// kit builds the tunneltest kit for one mode. The kit's Endpoints always
// arrive labelled mode=relay (it hands the factory what it was given); the
// factory is where this adapter decides which mode the run is for, so a
// reverse run really does start, carry, restart and refuse with Mode=reverse
// on the Spec — the rule CONTRACT §2.0 grades a mode on.
func kit(t *testing.T, mode string) tunneltest.Kit {
	t.Helper()
	alloc := tunnel.NewAllocator()
	return tunneltest.Kit{
		Adapter: Adapter{},
		NewSpec: func(e tunneltest.Endpoints) tunnel.Spec {
			// Three ports, one ingress: side a binds e.Listen (its relay), frpc
			// dials e.Listen+1 (frps bindPort) and frps listens for the proxy on
			// e.Listen+2. On side b, e.Peer is side a's ingress, so the shared
			// listen_port param carries the same number for both sides.
			ingress := e.Listen
			if e.Side == tunnel.SideB {
				ingress = e.Peer
			}
			_, port := mustHostPort(t, ingress)
			params := map[string]string{
				tunnel.ParamListenPort: strconv.Itoa(port),
				paramListenHost:        "127.0.0.1",
			}
			if e.Side == tunnel.SideB {
				host, _ := mustHostPort(t, e.Peer)
				targetHost, targetPort := mustHostPort(t, e.Target)
				params[paramServerAddr] = host
				params[paramLocalIP] = targetHost
				params[paramLocalPort] = strconv.Itoa(targetPort)
			}
			return tunnel.Spec{
				TunnelID:    e.TunnelID,
				Tool:        Tool,
				ToolVersion: Version,
				Side:        e.Side,
				Mode:        mode,
				Params:      params,
				Secrets:     map[string]string{SecretToken: ""},
				Enabled:     true,
			}
		},
		Allocate: func() tunnel.Ports { return alloc.AllocPair() },
		Corrupt: func(s *tunnel.Spec) {
			if s.Secrets == nil {
				s.Secrets = map[string]string{}
			}
			s.Secrets[SecretToken] = "deliberately-wrong-token"
		},
	}
}

func mustHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, raw, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("port in %q: %v", addr, err)
	}
	return host, port
}

// requireBinaries is the one permitted skip: Windows cannot run frps at all
// (Defender quarantines the exe — UPSTREAM.md), and a host with no offline
// bundle has nothing to run. Both are host-specific and stated; everywhere
// else a missing binary is a failure, not a skip.
func requireBinaries(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("frps.exe is quarantined by Windows Defender on this host (UPSTREAM.md); the four-part frp run is on the Linux test server")
	}
	if os.Getenv("TUNNEL_BUNDLE_DIR") == "" {
		t.Skip("TUNNEL_BUNDLE_DIR is not set on this host; the four-part frp run is on the Linux test server, where the offline bundle is verified")
	}
	if _, err := tunnel.ResolveBinary(Tool, ""); err != nil {
		t.Fatalf("frp binaries must resolve from the bundle: %v", err)
	}
}

// TestFourPartRelay is the reference run: traffic, restart, a corrupted token
// that fails explicitly, and logs that carry this tunnel_id and no other's.
func TestFourPartRelay(t *testing.T) {
	requireBinaries(t)
	t.Setenv(SecretToken, "four-part-secret")
	tunneltest.Run(t, kit(t, tunnel.ModeRelay))
}

// TestFourPartReverse is the same four steps against a reverse-mode Spec —
// frpc behind NAT dialling out, the service published on side a.
func TestFourPartReverse(t *testing.T) {
	requireBinaries(t)
	t.Setenv(SecretToken, "four-part-secret")
	tunneltest.Run(t, kit(t, tunnel.ModeReverse))
}

// TestTokenMismatchOpensNoProxyPort is the negative control the kit cannot
// make: it dials side a's ingress, which is this adapter's own relay and so
// is always bound. What must not open is frps's *proxy* port — the one a
// client would otherwise reach a tunnel through.
func TestTokenMismatchOpensNoProxyPort(t *testing.T) {
	requireBinaries(t)
	t.Setenv(SecretToken, "port-negative-secret")

	alloc := tunnel.NewAllocator()
	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: t.TempDir(), Allocator: alloc})
	t.Cleanup(m.Shutdown)

	portsA, portsB := alloc.AllocPair(), alloc.AllocPair()
	factory := kit(t, tunnel.ModeRelay).NewSpec
	epsA := tunneltest.Endpoints{
		TunnelID: "neg-port", Side: tunnel.SideA,
		Listen: net.JoinHostPort("127.0.0.1", strconv.Itoa(portsA.Listen)),
		Peer:   net.JoinHostPort("127.0.0.1", strconv.Itoa(portsB.Listen)),
		Target: "127.0.0.1:1", Mode: tunnel.ModeRelay,
	}
	epsB := epsA
	epsB.Side = tunnel.SideB
	epsB.Listen, epsB.Peer = epsA.Peer, epsA.Listen

	specA, specB := factory(epsA), factory(epsB)
	if err := m.Start(context.Background(), specA, portsA); err != nil {
		t.Fatalf("start side a: %v", err)
	}

	bad := specB.Clone()
	bad.Secrets[SecretToken] = "deliberately-wrong-token"
	startErr := m.Start(context.Background(), bad, portsB)
	if startErr == nil {
		t.Fatal("a wrong token must fail Start explicitly, not half-start frpc")
	}
	if !strings.Contains(startErr.Error(), "side=b") {
		t.Fatalf("error should name the side it failed on: %v", startErr)
	}
	t.Logf("wrong-token Start refused in-test: %v", startErr)

	// frps's proxy listener — listen_port+2, opened only when a client logs in
	// successfully — must still be closed.
	listenPort, err := strconv.Atoi(specA.Params[tunnel.ParamListenPort])
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort+2))
	conn, err := net.DialTimeout("tcp", proxyAddr, 500*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("frps opened its proxy port %s despite a refused login", proxyAddr)
	}
}

// TestRenderIsDeterministicAndTyped covers the render obligations without the
// kit: byte-identical output per Spec, the ports spelled out, and no secret.
func TestRenderIsDeterministicAndTyped(t *testing.T) {
	spec := tunnel.Spec{
		TunnelID: "render-1", Tool: Tool, ToolVersion: Version,
		Side: tunnel.SideA, Mode: tunnel.ModeRelay,
		Params: map[string]string{
			tunnel.ParamListenPort: "7100",
			paramListenHost:        "127.0.0.1",
			paramAdminPort:         "7401",
		},
		Secrets: map[string]string{SecretToken: "render-secret-value"},
	}
	a := Adapter{}
	first, err := a.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("renders differ:\n%s\n---\n%s", first, second)
	}
	for _, want := range []string{"bindPort = 7101", "webServer.port = 7401", "mode=relay"} {
		if !strings.Contains(first, want) {
			t.Fatalf("render is missing %q:\n%s", want, first)
		}
	}
	if strings.Contains(first, "render-secret-value") {
		t.Fatalf("a secret reached Render's output:\n%s", first)
	}

	// Both modes render — each has its own passing four-part run.
	spec.Mode = tunnel.ModeReverse
	reverse, err := a.Render(spec)
	if err != nil {
		t.Fatalf("reverse must render: %v", err)
	}
	if !strings.Contains(reverse, "mode=reverse") {
		t.Fatalf("reverse render does not say so:\n%s", reverse)
	}

	// Side b: serverPort = listen+1, remotePort = listen+2, localPort = relay.
	sideB := spec
	sideB.Side = tunnel.SideB
	sideB.Params = map[string]string{
		tunnel.ParamListenPort: "7100",
		paramServerAddr:        "10.0.0.9",
		paramLocalPort:         "8080",
	}
	b, err := a.Render(sideB)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`serverAddr = "10.0.0.9"`, "serverPort = 7101", "remotePort = 7102",
		"localPort = 7100", `type = "tcp"`, "loginFailExit = true",
	} {
		if !strings.Contains(b, want) {
			t.Fatalf("side b render is missing %q:\n%s", want, b)
		}
	}
}

// TestConfigValidation is the field-level refusal list: an untested type, a
// destination with no port, a host without a port — each named.
func TestConfigValidation(t *testing.T) {
	base := func() tunnel.Spec {
		return tunnel.Spec{
			TunnelID: "validate-1", Tool: Tool, Side: tunnel.SideB, Mode: tunnel.ModeRelay,
			Params: map[string]string{
				tunnel.ParamListenPort: "7100",
				paramServerAddr:        "10.0.0.9",
				paramLocalPort:         "8080",
			},
		}
	}
	a := Adapter{}

	spec := base()
	spec.Params[paramType] = "udp"
	_, err := a.Render(spec)
	if err == nil || !strings.Contains(err.Error(), paramType) {
		t.Fatalf("an untested proxy type must be refused by name, got %v", err)
	}

	spec = base()
	delete(spec.Params, paramLocalPort)
	_, err = a.Render(spec)
	if err == nil || !strings.Contains(err.Error(), paramLocalPort) || !strings.Contains(err.Error(), "localPort") {
		t.Fatalf("a missing local_port must name the param and the frp field, got %v", err)
	}

	spec = base()
	delete(spec.Params, paramServerAddr)
	_, err = a.Render(spec)
	if err == nil || !strings.Contains(err.Error(), paramServerAddr) {
		t.Fatalf("a missing server_addr must be named, got %v", err)
	}

	spec = base()
	spec.Params[tunnel.ParamListenPort] = "99999"
	_, err = a.Render(spec)
	if err == nil || !strings.Contains(err.Error(), tunnel.ParamListenPort) {
		t.Fatalf("an out-of-range listen_port must be named, got %v", err)
	}

	// Side a has no destination, but it does need a port the peer can dial.
	specA := base()
	specA.Side = tunnel.SideA
	specA.Params = map[string]string{paramListenHost: "127.0.0.1"}
	if _, err := a.Render(specA); err == nil || !strings.Contains(err.Error(), tunnel.ParamListenPort) {
		t.Fatalf("side a without listen_port must be refused, got %v", err)
	}
}

// TestValidateProxyBlocksRejectsDuplicateNames: frps keys proxies by name, so
// two blocks with one name is a config that half-works. Driven by hand-written
// text because Render only ever emits one proxy.
func TestValidateProxyBlocksRejectsDuplicateNames(t *testing.T) {
	dup := `
[[proxies]]
name = "pg-twin"
type = "tcp"
localIP = "127.0.0.1"
localPort = 9001

[[proxies]]
name = "pg-twin"
type = "tcp"
localIP = "127.0.0.1"
localPort = 9002
`
	err := validateProxyBlocks(dup)
	if err == nil || !strings.Contains(err.Error(), "name") || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate proxy name must be refused by name, got %v", err)
	}

	missingPort := `
[[proxies]]
name = "pg-noport"
type = "tcp"
localIP = "127.0.0.1"
`
	err = validateProxyBlocks(missingPort)
	if err == nil || !strings.Contains(err.Error(), "localPort") {
		t.Fatalf("a proxy with no localPort must be refused, got %v", err)
	}

	badType := `
[[proxies]]
name = "pg-http"
type = "http"
localIP = "127.0.0.1"
localPort = 80
`
	err = validateProxyBlocks(badType)
	if err == nil || !strings.Contains(err.Error(), "type") {
		t.Fatalf("an untested type in the text must be refused, got %v", err)
	}
}

// TestPinRefusesTamperedBinary is the install rule's negative control, on
// this platform's asset, with no real frp binary and no network anywhere.
func TestPinRefusesTamperedBinary(t *testing.T) {
	pin, ok := tunnel.PinFor(Tool)
	if !ok {
		t.Fatal("frp's pins.json did not register")
	}
	asset, err := pin.AssetFor(tunnel.PlatformKey())
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := peerAssets[tunnel.PlatformKey()]
	if !ok {
		t.Fatalf("no peer entry for %s", tunnel.PlatformKey())
	}

	dir := t.TempDir()
	rel := filepath.FromSlash(asset.Bin)
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755); err != nil {
		t.Fatal(err)
	}
	// Side a: the pinned frps path, wrong bytes.
	if err := os.WriteFile(filepath.Join(dir, rel), []byte("not-the-real-frps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := tunnel.ResolveBinary(Tool, dir); !errors.Is(err, tunnel.ErrBinaryMismatch) {
		t.Fatalf("tampered frps: want ErrBinaryMismatch, got %v", err)
	}
	// ...and the offline bundle with the right bytes resolves, offline.
	if err := os.WriteFile(filepath.Join(dir, rel), []byte("the-real-frps-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := tunnel.ResolveBinary(Tool, dir)
	if got != "" {
		t.Fatalf("a tampered bundle must not resolve, got %q", got)
	}

	// Side b: frpc is checked against the pin before it is ever exec'd.
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(peer.Bin)), []byte("tampered-frpc"), 0o755); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, rel)
	if _, err := frpcBinary(fake); !errors.Is(err, tunnel.ErrBinaryMismatch) {
		t.Fatalf("tampered frpc: want ErrBinaryMismatch, got %v", err)
	}
}

// TestPinResolvesOfflineBundle is the positive half: the pinned frps and frpc
// resolve out of the offline bundle, hash-verified, with no network. It needs
// the real binaries, which this host has only when it is the Linux test box.
func TestPinResolvesOfflineBundle(t *testing.T) {
	requireBinaries(t)
	bin, err := tunnel.ResolveBinary(Tool, "")
	if err != nil {
		t.Fatalf("frps must resolve offline: %v", err)
	}
	frpc, err := frpcBinary(bin)
	if err != nil {
		t.Fatalf("frpc must resolve offline: %v", err)
	}
	for _, path := range []string{bin, frpc} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPinMatchesTheUpstreamAsset pins the digests UPSTREAM.md recorded for
// fatedier/frp v0.71.0 — a pins.json that drifts from the published hashes
// would be a silent downgrade vector.
func TestPinMatchesTheUpstreamAsset(t *testing.T) {
	want := map[string]string{
		"frp_0.71.0_linux_amd64.tar.gz": "84f27e39f11169f7adcef8e8b70c9329de17747b1f14dad9fb95eef5682ea716",
		"frp_0.71.0_windows_amd64.zip":  "9e5062e3e5cf07e67144a3a4acf175ef6a2486f3605dd6cf288bae34ab39819f",
	}
	pin, ok := tunnel.PinFor(Tool)
	if !ok {
		t.Fatal("frp's pins.json did not register")
	}
	if pin.Version != Version {
		t.Fatalf("pin version %q, adapter version %q", pin.Version, Version)
	}
	if pin.Upstream != "fatedier/frp/releases/download/v0.71.0" {
		t.Fatalf("upstream = %q", pin.Upstream)
	}
	for platform, asset := range pin.Assets {
		sum, ok := want[asset.Name]
		if !ok {
			t.Fatalf("%s: unexpected asset %q", platform, asset.Name)
		}
		if asset.SHA256 != sum {
			t.Fatalf("%s: %s sha256 %s, UPSTREAM.md says %s", platform, asset.Name, asset.SHA256, sum)
		}
		if asset.Bin == "" || asset.BinSHA256 == "" || len(asset.BinSHA256) != 64 {
			t.Fatalf("%s: an archive asset must name the executable and its full sha256: %+v", platform, asset)
		}
		peer, ok := peerAssets[platform]
		if !ok || peer.Bin == "" || len(peer.BinSHA256) != 64 {
			t.Fatalf("%s: frpc must be pinned beside frps: %+v", platform, peer)
		}
	}
	if len(pin.Assets) != 2 || len(peerAssets) != 2 {
		t.Fatalf("want both platforms pinned, got %d assets and %d peers", len(pin.Assets), len(peerAssets))
	}
}

// TestPreflightNamesWhatIsMissing: a spec the host cannot run comes back as a
// Problem the panel can show, not a bare "failed to start".
func TestPreflightNamesWhatIsMissing(t *testing.T) {
	spec := tunnel.Spec{
		TunnelID: "pf-1", Tool: Tool, Side: tunnel.SideB, Mode: tunnel.ModeRelay,
		Params: map[string]string{tunnel.ParamListenPort: "7100", paramServerAddr: "10.0.0.9"},
	}
	problems := (Adapter{}).Preflight(context.Background(), spec)
	found := false
	for _, p := range problems {
		if p.Check == "params" && strings.Contains(p.Detail, paramLocalPort) {
			found = true
		}
	}
	if !found {
		t.Fatalf("preflight must report the missing local_port, got %v", problems)
	}
}
