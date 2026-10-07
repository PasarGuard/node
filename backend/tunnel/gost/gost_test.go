package gost

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/pasarguard/node/backend/tunnel"
	"github.com/pasarguard/node/backend/tunnel/tunneltest"
)

// TestFourPartRelay runs the shared four-part kit — traffic, restart, negative
// control, logs — in mode=relay. Both ends of the tunnel run in this process
// as real gost children of the pinned binary.
func TestFourPartRelay(t *testing.T) { runKit(t, tunnel.ModeRelay) }

// TestFourPartReverse runs the same kit in mode=reverse: side b sits behind
// NAT, dials side a, and the published port side a opens is the one the kit's
// client connects to (CONTRACT §2.0). Nothing here is skipped.
func TestFourPartReverse(t *testing.T) { runKit(t, tunnel.ModeReverse) }

func runKit(t *testing.T, mode string) {
	t.Setenv(SecretToken, "four-part-secret")
	t.Setenv("TUNNEL_BUNDLE_DIR", bundleDir(t))

	alloc := tunnel.NewAllocator()
	tunneltest.Run(t, tunneltest.Kit{
		Adapter:  Adapter{},
		NewSpec:  func(e tunneltest.Endpoints) tunnel.Spec { return kitSpec(mode, e) },
		Allocate: func() tunnel.Ports { return alloc.AllocPair() },
		Corrupt: func(s *tunnel.Spec) {
			// A wrong token on side b: in relay the start succeeds and the
			// handshake is refused with an explicit error record; in reverse
			// the registration never opens side a's port, so Start itself
			// fails. Either way nothing flows.
			if s.Secrets == nil {
				s.Secrets = map[string]string{}
			}
			s.Secrets[SecretToken] = "deliberately-wrong-token"
		},
	})
}

// kitSpec builds one side's Spec from the kit's endpoints. The panel sends one
// params map to both sides, so this factory only sets the keys the side reads.
func kitSpec(mode string, e tunneltest.Endpoints) tunnel.Spec {
	params := map[string]string{
		tunnel.ParamListenPort: portOf(e.Listen),
		ParamListenHost:        "127.0.0.1",
	}
	switch {
	case mode == tunnel.ModeRelay && e.Side == tunnel.SideA:
		params[ParamPeer] = e.Peer
		params[ParamTarget] = e.Target
	case mode == tunnel.ModeReverse && e.Side == tunnel.SideB:
		// Side a publishes on its listen port and listens for us on listen+1
		// (the framework's Control rule, CONTRACT §1.4).
		params[ParamPeer] = controlOf(e.Peer)
		params[ParamPublish] = e.Peer
		params[ParamTarget] = e.Target
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
}

// TestRenderIsDeterministicAndSchema covers the render obligations the kit
// does not: byte-identical output for one Spec in both modes, an unknown param
// refused BY NAME, a missing required param refused BY NAME, and a mode outside
// CONTRACT §2.0 refused outright.
func TestRenderIsDeterministicAndSchema(t *testing.T) {
	a := Adapter{}
	for _, mode := range []string{tunnel.ModeRelay, tunnel.ModeReverse} {
		for _, side := range []tunnel.Side{tunnel.SideA, tunnel.SideB} {
			spec := specFor(mode, side)
			first, err := a.Render(spec)
			if err != nil {
				t.Fatalf("render %s/%s: %v", mode, side, err)
			}
			second, err := a.Render(spec)
			if err != nil {
				t.Fatalf("second render %s/%s: %v", mode, side, err)
			}
			if first != second {
				t.Fatalf("render is not deterministic for %s/%s:\n%s\n---\n%s", mode, side, first, second)
			}
			if !strings.Contains(first, `"type": "`) {
				t.Fatalf("render for %s/%s has no handler/listener type:\n%s", mode, side, first)
			}
		}
	}

	// A typo must not become a running tunnel with default settings: the
	// error names the key.
	bad := specFor(tunnel.ModeRelay, tunnel.SideA)
	bad.Params["targt"] = "127.0.0.1:1"
	if _, err := a.Render(bad); err == nil {
		t.Fatal("params.targt must be refused")
	} else if !strings.Contains(err.Error(), `"targt"`) {
		t.Fatalf("the refusal must name the key, got: %v", err)
	}

	// A required key that is absent is refused by name too.
	missing := specFor(tunnel.ModeRelay, tunnel.SideA)
	delete(missing.Params, ParamTarget)
	if _, err := a.Render(missing); err == nil || !strings.Contains(err.Error(), ParamTarget) {
		t.Fatalf("a missing %s must be refused by name, got: %v", ParamTarget, err)
	}

	// A mode outside the contract never reaches gost's schema.
	smtp := specFor(tunnel.ModeRelay, tunnel.SideA)
	smtp.Mode = "smtp"
	if _, err := a.Render(smtp); !errors.Is(err, tunnel.ErrInvalidSpec) {
		t.Fatalf("mode=smtp: got %v, want ErrInvalidSpec", err)
	}
}

// TestBinaryPin is the install rule (CONTRACT §2.1): the offline bundle's
// binary starts, a bundle whose gost is not byte-identical to the pin is
// refused, and nothing on either path touches the network.
func TestBinaryPin(t *testing.T) {
	real := bundleDir(t)
	t.Setenv("TUNNEL_BUNDLE_DIR", real)
	if _, err := tunnel.ResolveBinary(Tool, ""); err != nil {
		t.Fatalf("the offline bundle must satisfy the pin: %v", err)
	}

	tampered := t.TempDir()
	src := filepath.Join(real, gostBin())
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read pinned binary: %v", err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(filepath.Join(tampered, gostBin()), data, 0o755); err != nil {
		t.Fatalf("write tampered binary: %v", err)
	}
	t.Setenv("TUNNEL_BUNDLE_DIR", tampered)
	if _, err := tunnel.ResolveBinary(Tool, ""); !errors.Is(err, tunnel.ErrBinaryMismatch) {
		t.Fatalf("a binary whose sha256 is not the pin must be refused, got: %v", err)
	}
}

// specFor is a complete Spec for one mode/side, used by the render tests.
func specFor(mode string, side tunnel.Side) tunnel.Spec {
	params := map[string]string{
		tunnel.ParamListenPort: "20123",
		ParamListenHost:        "127.0.0.1",
		ParamPeer:              "127.0.0.1:20456",
		ParamTarget:            "127.0.0.1:20789",
		ParamPublish:           "127.0.0.1:20123",
	}
	return tunnel.Spec{
		TunnelID: "render-1",
		Tool:     Tool,
		Side:     side,
		Mode:     mode,
		Params:   params,
		Secrets:  map[string]string{SecretToken: "secret-value"},
		Enabled:  true,
	}
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "0"
	}
	return port
}

// controlOf is the framework's Control = Listen+1 rule (CONTRACT §1.4) as an
// address: side a's control port, which side b dials in mode=reverse.
func controlOf(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(host, strconv.Itoa(n+1))
}

func gostBin() string {
	if runtime.GOOS == "windows" {
		return "gost.exe"
	}
	return "gost"
}

// bundleDir locates the offline bundle: TUNNEL_BUNDLE_DIR when the operator
// set one, else tools/tunnel-bundle next to this checkout. A test that cannot
// find the binary FAILS — it never skips, because a skipped four-part run
// proves nothing.
func bundleDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("TUNNEL_BUNDLE_DIR"); dir != "" {
		if _, err := os.Stat(filepath.Join(dir, gostBin())); err == nil {
			return dir
		}
	}
	sub := "linux"
	if runtime.GOOS == "windows" {
		sub = "win"
	}
	here, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve package dir: %v", err)
	}
	root := filepath.Join(here, "..", "..", "..", "..")
	for _, dir := range []string{
		filepath.Join(root, "tunnel-bundle", sub),
		filepath.Join(root, "tunnel-bundle"),
	} {
		if _, err := os.Stat(filepath.Join(dir, gostBin())); err == nil {
			return dir
		}
	}
	t.Fatalf("gost binary not found: set TUNNEL_BUNDLE_DIR to a bundle holding %s (tried %s and %s)",
		gostBin(), filepath.Join(root, "tunnel-bundle", sub), filepath.Join(root, "tunnel-bundle"))
	return ""
}
