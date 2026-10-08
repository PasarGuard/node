package wstunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/backend/tunnel/tunneltest"
)

const kitToken = "four-part-secret"

// setBundle points the pin resolver at an offline bundle. No download and no
// network are involved: when nothing local can be found the test fails
// instead of reaching for the internet.
func setBundle(t *testing.T) {
	t.Helper()
	if os.Getenv("TUNNEL_BUNDLE_DIR") != "" {
		return
	}
	pin, ok := tunnel.PinFor(Tool)
	if !ok {
		t.Fatal("wstunnel pin is not registered")
	}
	asset, err := pin.AssetFor(tunnel.PlatformKey())
	if err != nil {
		t.Fatal(err)
	}
	binName := asset.Bin
	if binName == "" {
		binName = asset.Name
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{
		filepath.Join(root, "..", "tunnel-bundle", "win"),
		filepath.Join(root, "..", "tunnel-bundle", "linux"),
		filepath.Join(root, "..", "tunnel-bundle", "linux", "wstunnel"),
	} {
		if st, err := os.Stat(filepath.Join(dir, binName)); err == nil && !st.IsDir() {
			t.Setenv("TUNNEL_BUNDLE_DIR", dir)
			return
		}
	}
	t.Fatalf("wstunnel: %s not found in the offline bundle; set TUNNEL_BUNDLE_DIR to a directory holding it", binName)
}

// specFactory builds one relay side. side a dials e.Peer and delivers to
// e.Target, side b just listens: the destination travels in side a's -L.
func relaySpec(e tunneltest.Endpoints) tunnel.Spec {
	return tunnel.Spec{
		TunnelID:    e.TunnelID,
		Tool:        Tool,
		ToolVersion: Version,
		Side:        e.Side,
		Mode:        e.Mode,
		Params: map[string]string{
			paramListenHost: "127.0.0.1",
			paramPeer:       e.Peer,
			paramTarget:     e.Target,
		},
		Secrets: map[string]string{SecretToken: ""},
		Enabled: true,
	}
}

func relayKit(t *testing.T, extra func(*tunnel.Spec)) tunneltest.Kit {
	t.Helper()
	setBundle(t)
	// A mirror that cannot answer: nothing may be fetched at Start.
	t.Setenv("TUNNEL_GITHUB_MIRROR", "http://127.0.0.1:9")
	t.Setenv(SecretToken, kitToken)

	alloc := tunnel.NewAllocator()
	kit := tunneltest.Kit{
		Adapter:  Adapter{},
		NewSpec:  relaySpec,
		Allocate: func() tunnel.Ports { return alloc.AllocPair(extraInner) },
		Corrupt: func(s *tunnel.Spec) {
			if s.Secrets == nil {
				s.Secrets = map[string]string{}
			}
			s.Secrets[SecretToken] = "deliberately-wrong-token"
		},
	}
	if extra != nil {
		base := kit.NewSpec
		kit.NewSpec = func(e tunneltest.Endpoints) tunnel.Spec {
			s := base(e)
			extra(&s)
			return s
		}
	}
	return kit
}

// TestFourPartRelay is the four-part testkit: determinism, traffic, restart,
// a corrupted secret, log isolation — all five steps, zero skips.
func TestFourPartRelay(t *testing.T) {
	tunneltest.Run(t, relayKit(t, nil))
}

// TestFourPartRelayWSS runs the same five steps over TLS (transport=wss), so
// the certificate knobs are proven by traffic rather than by inspection.
func TestFourPartRelayWSS(t *testing.T) {
	cert, key := writeTestCert(t)
	tunneltest.Run(t, relayKit(t, func(s *tunnel.Spec) {
		s.Params[paramTransport] = "wss"
		if s.Side == tunnel.SideB {
			s.Params[paramTLSCert] = cert
			s.Params[paramTLSKey] = key
		}
	}))
}

// TestRenderIsDeterministicAndNeverLeaksTheToken covers Render's obligations:
// byte-identical output, the shape spelled out, and no secret value on disk.
func TestRenderIsDeterministicAndNeverLeaksTheToken(t *testing.T) {
	spec := relaySpec(tunneltest.Endpoints{
		TunnelID: "render-1", Side: tunnel.SideA, Mode: tunnel.ModeRelay,
		Peer: "127.0.0.1:25001", Target: "127.0.0.1:25002",
	})
	spec.Secrets[SecretToken] = "super-secret-value"
	spec.Params[tunnel.ParamListenPort] = "25100"

	first, err := Adapter{}.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Adapter{}.Render(spec)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("Render is not deterministic:\n%s\n---\n%s", first, second)
	}
	if strings.Contains(first, "super-secret-value") {
		t.Fatalf("Render leaked the token:\n%s", first)
	}
	if !strings.Contains(first, secretPlaceholder) {
		t.Fatalf("Render must print %s, got:\n%s", secretPlaceholder, first)
	}
	for _, want := range []string{"mode=relay", "side=a", "role=client", " -L ", "tcp://127.0.0.1:25101:127.0.0.1:25002"} {
		if !strings.Contains(first, want) {
			t.Fatalf("Render is missing %q:\n%s", want, first)
		}
	}
}

// TestRenderRefusesWhatItCannotRun: an unsupported mode, a TLS certificate
// that does not exist, and a destination allowlist on a side that would not
// enforce it — all refused by Render, not at first connection.
func TestRenderRefusesWhatItCannotRun(t *testing.T) {
	a := Adapter{}

	spec := relaySpec(tunneltest.Endpoints{
		TunnelID: "r-mode", Side: tunnel.SideA, Mode: "smtp",
		Peer: "127.0.0.1:1", Target: "127.0.0.1:2",
	})
	spec.Mode = "smtp"
	if _, err := a.Render(spec); !errors.Is(err, tunnel.ErrInvalidSpec) {
		t.Fatalf("a mode outside CONTRACT 2.0 must be ErrInvalidSpec, got %v", err)
	}

	tls := relaySpec(tunneltest.Endpoints{
		TunnelID: "r-tls", Side: tunnel.SideB, Mode: tunnel.ModeRelay,
		Peer: "127.0.0.1:1", Target: "127.0.0.1:2",
	})
	tls.Params[paramTransport] = "wss"
	tls.Params[paramTLSCert] = filepath.Join(t.TempDir(), "absent.pem")
	tls.Params[paramTLSKey] = filepath.Join(t.TempDir(), "absent.key")
	_, err := a.Render(tls)
	if err == nil || !strings.Contains(err.Error(), "not readable") {
		t.Fatalf("a missing certificate must fail at Render, got %v", err)
	}

	// A real certificate pair renders.
	cert, key := writeTestCert(t)
	tls.Params[paramTLSCert], tls.Params[paramTLSKey] = cert, key
	if _, err := a.Render(tls); err != nil {
		t.Fatalf("present TLS material must render, got %v", err)
	}

	// restrict_to on a side that never dials a destination is not enforced,
	// so it is refused rather than silently dropped.
	rl := relaySpec(tunneltest.Endpoints{
		TunnelID: "r-restrict", Side: tunnel.SideA, Mode: tunnel.ModeRelay,
		Peer: "127.0.0.1:1", Target: "127.0.0.1:2",
	})
	rl.Params[paramRestrictTo] = "127.0.0.1:2"
	if _, err := a.Render(rl); err == nil || !strings.Contains(err.Error(), paramRestrictTo) {
		t.Fatalf("restrict_to on side a must be refused, got %v", err)
	}
}

// TestStartRefusesUnauthenticated: no token, no tunnel. An empty secret is
// the same refusal as an unresolved one (CONTRACT §2.1).
func TestStartRefusesUnauthenticated(t *testing.T) {
	setBundle(t)
	spec := relaySpec(tunneltest.Endpoints{
		TunnelID: "no-token", Side: tunnel.SideB, Mode: tunnel.ModeRelay,
		Peer: "127.0.0.1:1", Target: "127.0.0.1:2",
	})
	spec.Secrets[SecretToken] = ""
	spec.Params[tunnel.ParamBinaryPath] = "C:\\nope\\wstunnel.exe"
	_, err := Adapter{}.Start(context.Background(), spec, tunnel.Ports{Listen: 26001, Control: 26002})
	if !errors.Is(err, tunnel.ErrSecretUnresolved) {
		t.Fatalf("want ErrSecretUnresolved, got %v", err)
	}
}

// TestPreflight: what this host cannot do has to be reported, and a ready
// side has to report nothing.
func TestPreflight(t *testing.T) {
	setBundle(t)
	ready := relaySpec(tunneltest.Endpoints{
		TunnelID: "pf-ok", Side: tunnel.SideB, Mode: tunnel.ModeRelay,
		Peer: "127.0.0.1:1", Target: "127.0.0.1:2",
	})
	if got := (Adapter{}).Preflight(context.Background(), ready); len(got) != 0 {
		t.Fatalf("a valid relay side should be ready, got %v", got)
	}

	// A server bound past loopback with no destination allowlist is an open
	// relay; Preflight says so instead of letting Start discover it.
	open := relaySpec(tunneltest.Endpoints{
		TunnelID: "pf-open", Side: tunnel.SideB, Mode: tunnel.ModeRelay,
		Peer: "127.0.0.1:1", Target: "127.0.0.1:2",
	})
	open.Params[paramListenHost] = "0.0.0.0"
	got := (Adapter{}).Preflight(context.Background(), open)
	if len(got) == 0 || !strings.Contains(got[0].Detail, "open relay") {
		t.Fatalf("an open-relay spec must be reported, got %v", got)
	}
}

// TestPinRefusesATamperedBinary: the offline bundle runs only if its sha256
// is the pin's. One flipped byte and the resolver refuses it.
func TestPinRefusesATamperedBinary(t *testing.T) {
	setBundle(t)
	bundle := os.Getenv("TUNNEL_BUNDLE_DIR")
	pin, _ := tunnel.PinFor(Tool)
	asset, err := pin.AssetFor(tunnel.PlatformKey())
	if err != nil {
		t.Fatal(err)
	}
	binName := asset.Bin
	if binName == "" {
		binName = asset.Name
	}
	original, err := os.ReadFile(filepath.Join(bundle, binName))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	tampered := append([]byte(nil), original...)
	tampered[len(tampered)/2] ^= 0xff
	if err := os.WriteFile(filepath.Join(dir, binName), tampered, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := tunnel.ResolveBinary(Tool, dir); !errors.Is(err, tunnel.ErrBinaryMismatch) {
		t.Fatalf("a tampered binary must be ErrBinaryMismatch, got %v", err)
	}

	// ...and the untouched bundle resolves, with no network anywhere:
	// TUNNEL_GITHUB_MIRROR cannot answer and nothing calls it.
	t.Setenv("TUNNEL_GITHUB_MIRROR", "http://127.0.0.1:9")
	got, err := tunnel.ResolveBinary(Tool, bundle)
	if err != nil {
		t.Fatalf("the offline bundle must resolve: %v", err)
	}
	sum, err := tunnel.FileSHA256(got)
	if err != nil {
		t.Fatal(err)
	}
	want := asset.BinSHA256
	if want == "" {
		want = asset.SHA256
	}
	if !strings.EqualFold(sum, want) {
		t.Fatalf("resolved %s has sha256 %s, pin wants %s", got, sum, want)
	}
}

// TestRestrictToRestricts proves the destination allowlist actually filters:
// a permitted destination round-trips, a non-permitted one delivers nothing.
func TestRestrictToRestricts(t *testing.T) {
	setBundle(t)
	t.Setenv(SecretToken, kitToken)
	t.Setenv("TUNNEL_GITHUB_MIRROR", "http://127.0.0.1:9")

	allowed := newEchoSink(t)
	defer allowed.close()
	forbidden := newEchoSink(t)
	defer forbidden.close()

	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: t.TempDir()})
	t.Cleanup(m.Shutdown)
	alloc := tunnel.NewAllocator()
	portsA, portsB := alloc.AllocPair(extraInner), alloc.AllocPair(extraInner)

	const id = "restrict-1"
	srvSpec := tunnel.Spec{
		TunnelID: id, Tool: Tool, ToolVersion: Version, Side: tunnel.SideB, Mode: tunnel.ModeRelay,
		Params: map[string]string{
			paramListenHost: "127.0.0.1",
			paramRestrictTo: allowed.addr(),
		},
		Secrets: map[string]string{SecretToken: ""}, Enabled: true,
	}
	// side a is deliberately pointed at the forbidden destination.
	cliSpec := tunnel.Spec{
		TunnelID: id, Tool: Tool, ToolVersion: Version, Side: tunnel.SideA, Mode: tunnel.ModeRelay,
		Params: map[string]string{
			paramListenHost: "127.0.0.1",
			paramPeer:       fmt.Sprintf("127.0.0.1:%d", portsB.Listen),
			paramTarget:     forbidden.addr(),
		},
		Secrets: map[string]string{SecretToken: ""}, Enabled: true,
	}

	if err := m.Start(context.Background(), srvSpec, portsB); err != nil {
		t.Fatalf("start server: %v", err)
	}
	// A permissive server first: the allowlist must not block a destination
	// it does name, so side a is restarted against the allowed one.
	permissive := cliSpec.Clone()
	permissive.Params[paramTarget] = allowed.addr()
	if err := m.Start(context.Background(), permissive, portsA); err != nil {
		t.Fatalf("start client (allowed): %v", err)
	}
	if err := roundTrip(ingress(portsA.Listen), allowed); err != nil {
		t.Fatalf("permitted destination: %v", err)
	}
	if err := m.Stop(id); err != nil {
		t.Fatal(err)
	}

	// Now the forbidden destination: nothing must arrive.
	if err := m.Start(context.Background(), srvSpec, portsB); err != nil {
		t.Fatalf("restart server: %v", err)
	}
	if err := m.Start(context.Background(), cliSpec, portsA); err != nil {
		t.Fatalf("start client (forbidden): %v", err)
	}
	before := forbidden.received()
	conn, err := net.DialTimeout("tcp", ingress(portsA.Listen), 5*time.Second)
	if err != nil {
		t.Fatalf("dial ingress: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("must-not-arrive"))
	buf := make([]byte, 16)
	_, _ = conn.Read(buf)
	_ = conn.Close()
	time.Sleep(300 * time.Millisecond)
	if got := forbidden.received() - before; got != 0 {
		t.Fatalf("restricted destination received %d bytes", got)
	}
	// And the refusal is an explicit record, not silence.
	if !hasError(m.Logs(id)) {
		t.Fatal("a rejected destination produced no Error-level log record")
	}
}

// TestReverseLoopback is mode=reverse's own four-part run: side a publishes,
// side b dials out with -R, bytes enter at a and reach the service behind b.
func TestReverseLoopback(t *testing.T) {
	setBundle(t)
	t.Setenv(SecretToken, kitToken)
	t.Setenv("TUNNEL_GITHUB_MIRROR", "http://127.0.0.1:9")

	sink := newEchoSink(t)
	defer sink.close()

	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: t.TempDir()})
	t.Cleanup(m.Shutdown)
	alloc := tunnel.NewAllocator()
	portsA, portsB := alloc.AllocPair(extraInner), alloc.AllocPair(extraInner)

	const id = "reverse-1"
	specA := tunnel.Spec{
		TunnelID: id, Tool: Tool, ToolVersion: Version, Side: tunnel.SideA, Mode: tunnel.ModeReverse,
		Params:  map[string]string{paramListenHost: "127.0.0.1"},
		Secrets: map[string]string{SecretToken: ""}, Enabled: true,
	}
	specB := tunnel.Spec{
		TunnelID: id, Tool: Tool, ToolVersion: Version, Side: tunnel.SideB, Mode: tunnel.ModeReverse,
		Params: map[string]string{
			paramListenHost: "127.0.0.1",
			paramPeer:       fmt.Sprintf("127.0.0.1:%d", portsA.Listen), // side a publishes this
			paramTarget:     sink.addr(),                                // the service behind b
		},
		Secrets: map[string]string{SecretToken: ""}, Enabled: true,
	}

	// 1. Render is deterministic for both sides.
	for _, spec := range []tunnel.Spec{specA, specB} {
		one, err := Adapter{}.Render(spec)
		if err != nil {
			t.Fatalf("render %s: %v", spec.Side, err)
		}
		two, err := Adapter{}.Render(spec)
		if err != nil {
			t.Fatal(err)
		}
		if one != two {
			t.Fatalf("reverse render for side %s is not deterministic:\n%s\n---\n%s", spec.Side, one, two)
		}
		if strings.Contains(one, kitToken) {
			t.Fatalf("reverse render leaked the token:\n%s", one)
		}
	}

	// 2. Traffic: bytes enter at side a's published port, leave behind side b.
	if err := m.Start(context.Background(), specA, portsA); err != nil {
		t.Fatalf("start side a: %v", err)
	}
	if err := m.Start(context.Background(), specB, portsB); err != nil {
		t.Fatalf("start side b: %v", err)
	}
	if err := reverseRoundTrip(portsA.Listen, sink); err != nil {
		t.Fatalf("reverse traffic: %v", err)
	}
	for _, st := range m.List() {
		if st.BytesUp == 0 || st.BytesDown == 0 {
			t.Fatalf("reverse stats for %s side %s: up=%d down=%d", st.TunnelID, st.Side, st.BytesUp, st.BytesDown)
		}
	}

	// 3. Restart from the same Spec: stop, re-render, start, traffic again.
	if err := m.Stop(id); err != nil {
		t.Fatal(err)
	}
	if _, err := (Adapter{}).Render(specA); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background(), specA, portsA); err != nil {
		t.Fatalf("restart side a: %v", err)
	}
	if err := m.Start(context.Background(), specB, portsB); err != nil {
		t.Fatalf("restart side b: %v", err)
	}
	if err := reverseRoundTrip(portsA.Listen, sink); err != nil {
		t.Fatalf("reverse traffic after restart: %v", err)
	}

	// 4. Negative control: a corrupted secret on side b. Start must fail
	// outright — side a never publishes for a client it will not admit — and
	// the destination must not see a byte.
	if err := m.Stop(id); err != nil {
		t.Fatal(err)
	}
	bad := specB.Clone()
	bad.Secrets[SecretToken] = "deliberately-wrong-token"
	before := sink.received()
	if err := m.Start(context.Background(), specA, portsA); err != nil {
		t.Fatalf("start side a: %v", err)
	}
	// The refusal is explicit: side a never publishes for a client it will
	// not admit, so side b's readiness check fails and Start returns the
	// error rather than a handle that silently carries nothing.
	if err := m.Start(context.Background(), bad, portsB); err == nil {
		t.Fatal("a corrupted secret must refuse to start")
	}
	_ = dialAndWrite(portsA.Listen, []byte("must-not-arrive")) // expected: nothing is published
	time.Sleep(300 * time.Millisecond)
	if got := sink.received() - before; got != 0 {
		t.Fatalf("corrupted secret: %d bytes reached the destination", got)
	}

	// 5. Logs are addressable by tunnel_id and mention no other tunnel.
	recs := m.Logs(id)
	if len(recs) == 0 {
		t.Fatal("no log records for this tunnel")
	}
	for _, rec := range recs {
		if rec.TunnelID != id {
			t.Fatalf("record carries tunnel_id %q", rec.TunnelID)
		}
	}
	if err := m.Stop(id); err != nil {
		t.Fatal(err)
	}
}

// ------------------------------------------------------------------ helpers

func ingress(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) }

// roundTrip pushes a payload through addr and requires the echo back, then
// waits for the sink to have seen the payload.
func roundTrip(addr string, sink *echoSink) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	for i := range payload {
		if payload[i] != got[i] {
			return fmt.Errorf("echo differs at byte %d", i)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for sink.received() < len(payload) {
		if time.Now().After(deadline) {
			return fmt.Errorf("sink saw %d of %d bytes", sink.received(), len(payload))
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

// reverseRoundTrip is roundTrip for mode=reverse: side a's published port is
// the ingress, and the sink sits behind side b.
func reverseRoundTrip(port int, sink *echoSink) error {
	return roundTrip(ingress(port), sink)
}

func dialAndWrite(port int, payload []byte) error {
	conn, err := net.DialTimeout("tcp", ingress(port), 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	buf := make([]byte, len(payload))
	_, _ = conn.Read(buf)
	return nil
}

func hasError(recs []tunnel.Record) bool {
	for _, r := range recs {
		if r.Level == "Error" {
			return true
		}
	}
	return false
}

// echoSink is a loopback server that echoes everything it receives and counts
// the bytes — the destination side b delivers to.
type echoSink struct {
	ln  net.Listener
	mu  sync.Mutex
	got int
}

func newEchoSink(t *testing.T) *echoSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &echoSink{ln: ln}
	go s.serve()
	return s
}

func (s *echoSink) addr() string { return s.ln.Addr().String() }
func (s *echoSink) close()       { _ = s.ln.Close() }

func (s *echoSink) received() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got
}

func (s *echoSink) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(15 * time.Second))
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					s.mu.Lock()
					s.got += n
					s.mu.Unlock()
					if _, werr := c.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}(conn)
	}
}

// writeTestCert mints a self-signed certificate pair for the wss tests.
func writeTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wstunnel.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// TestReverseSideADerivesInnerFromListen pins the derivation the panel path
// depends on: the RPC layer hands over Listen+Control only, so reverse side a
// takes the websocket entry from Listen+2. Without this, wstunnel/reverse can
// pass the four-part kit (which allocates Extra) and still be unstartable
// from the panel — that gap is what the round-2a reverse E2E hit.
func TestReverseSideADerivesInnerFromListen(t *testing.T) {
	spec := tunnel.Spec{
		TunnelID: "derive-inner", Tool: Tool, Side: tunnel.SideA, Mode: tunnel.ModeReverse,
		Params: map[string]string{tunnel.ParamListenPort: "47869", paramTarget: "127.0.0.1:8199"},
		Secrets: map[string]string{SecretToken: "tok"},
	}
	ports := tunnel.Ports{Listen: 47869, Control: 47870}
	p, err := newPlan(spec, ports)
	if err != nil {
		t.Fatalf("newPlan: %v", err)
	}
	if p.inner != 47871 {
		t.Fatalf("inner = %d, want Listen+2 = 47871", p.inner)
	}
	if _, err := (Adapter{}).Start(context.Background(), spec, ports); err == nil {
		t.Fatal("Start must still refuse without a resolved binary; the plan is what this test pins")
	}
}
