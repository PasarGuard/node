package udp2raw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/pasarguard/node/backend/tunnel"
)

// udp2raw cannot run the shared four-part kit (tunneltest.Run): the kit's
// byte sink is a TCP listener on 127.0.0.1, and this tool needs a raw socket,
// CAP_NET_RAW and two network namespaces with a veth between them (CONTRACT
// §2.3). The four stages below are hand-written instead — precedent:
// wstunnel's reverse stages and backhaul's TestFourPartReverse — and each one
// is named in its own output:
//
//	traffic           — UDP datagrams through the tunnel, byte-for-byte both
//	                    ways, and the destination's own digest proves the bytes
//	                    arrived there
//	restart           — stop, re-Render (byte-identical), start again with no
//	                    manual step, traffic again
//	negative-control  — an unresolved key is refused by Start; a WRONG key
//	                    starts the process and still carries nothing, and the
//	                    handshake is seen never completing
//	logs              — every record in this tunnel's ring carries this
//	                    tunnel_id, and no line crosses to a decoy tunnel
//
// Render determinism, the binary pin and the raw-socket preflight live here and
// run on any host; netns_test.go (linux) holds the four stages.

// ---------------------------------------------------------------------------
// render / schema (any host)

// TestRenderIsDeterministicAndSchema covers the render obligations: identical
// output for one Spec, an unknown param refused BY NAME, a missing required
// param refused BY NAME, a mode outside CONTRACT §2.0 refused outright, and a
// value the pinned build would reject refused by name.
func TestRenderIsDeterministicAndSchema(t *testing.T) {
	a := Adapter{}
	for _, side := range []tunnel.Side{tunnel.SideA, tunnel.SideB} {
		spec := specFor(tunnel.ModeRelay, side)
		first, err := a.Render(spec)
		if err != nil {
			t.Fatalf("render relay/%s: %v", side, err)
		}
		second, err := a.Render(spec)
		if err != nil {
			t.Fatalf("second render relay/%s: %v", side, err)
		}
		if first != second {
			t.Fatalf("render is not deterministic for relay/%s:\n%s\n---\n%s", side, first, second)
		}
		if !strings.Contains(first, "-l 0.0.0.0:20123") {
			t.Fatalf("render for relay/%s has no -l line:\n%s", side, first)
		}
		if !strings.Contains(first, "-k "+spec.Secrets[SecretKey]) {
			t.Fatalf("render for relay/%s dropped the key it cannot start without:\n%s", side, first)
		}
	}

	// A typo must not become a running tunnel with default settings.
	bad := specFor(tunnel.ModeRelay, tunnel.SideA)
	bad.Params["targt"] = "10.0.0.1:1"
	if _, err := a.Render(bad); err == nil {
		t.Fatal("params.targt must be refused")
	} else if !strings.Contains(err.Error(), `"targt"`) {
		t.Fatalf("the refusal must name the key, got: %v", err)
	}

	// A required key that is absent is refused by name too.
	missing := specFor(tunnel.ModeRelay, tunnel.SideA)
	delete(missing.Params, ParamPeer)
	if _, err := a.Render(missing); err == nil || !strings.Contains(err.Error(), ParamPeer) {
		t.Fatalf("a missing %s must be refused by name, got: %v", ParamPeer, err)
	}

	// A value the pinned build's own --help does not offer is refused, not
	// passed through to a process that would exit on it.
	badMode := specFor(tunnel.ModeRelay, tunnel.SideA)
	badMode.Params[ParamRawMode] = "faketls"
	if _, err := a.Render(badMode); err == nil || !strings.Contains(err.Error(), ParamRawMode) {
		t.Fatalf("raw_mode=faketls must be refused by name, got: %v", err)
	}

	// reverse was never tested for this tool: refuse it, never fall through.
	rev := specFor(tunnel.ModeReverse, tunnel.SideA)
	if _, err := a.Render(rev); !errors.Is(err, tunnel.ErrModeUnsupported) {
		t.Fatalf("mode=reverse: got %v, want ErrModeUnsupported", err)
	}

	// No key, no config: an empty secret must not render a tunnel udp2raw
	// would start with its own public default key.
	noKey := specFor(tunnel.ModeRelay, tunnel.SideA)
	noKey.Secrets = map[string]string{}
	if _, err := a.Render(noKey); !errors.Is(err, tunnel.ErrSecretUnresolved) {
		t.Fatalf("render without the key: got %v, want ErrSecretUnresolved", err)
	}
}

// ---------------------------------------------------------------------------
// binary pin (any host): a wrong sha256 must be refused before exec

// TestBinaryPin is the install rule's negative control (CONTRACT §2.1): the
// bytes at the pin's own path are wrong, so ResolveBinary refuses them with
// ErrBinaryMismatch — on every host, Windows included, where the fat bundle
// ships no Windows build at all and the pin's asset is retargeted under this
// platform key to exercise the same refusal (the archive is one file for
// every platform; pins.json may list it once, see docs/multi/tunnels/udp2raw.md).
// The matching-bytes half of the rule runs in requireBinary, on the host that
// has the real bundle.
func TestBinaryPin(t *testing.T) {
	pin, ok := tunnel.PinFor(Tool)
	if !ok {
		t.Fatal("pins.json is not registered")
	}
	asset, err := pin.AssetFor(tunnel.PlatformKey())
	probeName := Tool
	if err != nil {
		base, ok := pin.Assets["linux-amd64"]
		if !ok {
			t.Fatalf("pin has no linux-amd64 asset: %v", err)
		}
		probe := pin
		probe.Tool = Tool + "-pinprobe"
		probe.Assets = map[string]tunnel.PinAsset{tunnel.PlatformKey(): base}
		if err := tunnel.RegisterPin(probe); err != nil {
			t.Fatalf("retarget pin: %v", err)
		}
		defer func() {
			// Restore the shipped pin under its own name; the probe entry
			// stays registered the way pins_test.go's own temp pins do.
			_ = tunnel.RegisterPinJSON(pinsJSON, "pins.json")
		}()
		asset = base
		probeName = probe.Tool
	}

	// The refusal itself: one flipped byte and nothing runs.
	tampered := t.TempDir()
	good := []byte("udp2raw-pin-h") // deliberately not the pinned bytes
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 0xff
	writeFile(t, filepath.Join(tampered, asset.Bin), bad, 0o755)
	t.Setenv("TUNNEL_BUNDLE_DIR", tampered)
	got, err := tunnel.ResolveBinary(probeName, tampered)
	if !errors.Is(err, tunnel.ErrBinaryMismatch) {
		t.Fatalf("a binary whose sha256 is not the pin's must be refused, got path=%q err=%v", got, err)
	}
}

// ---------------------------------------------------------------------------
// preflight: the raw-socket requirement is reported BEFORE Start

// TestPreflightNamesRawSocket pins down CONTRACT §2.3 for this tool: the
// problem carries the framework's own check name, and where the host really
// lacks the grant the fix says which one to give — and Start refuses with
// that text instead of letting udp2raw die on a bare permission denied.
func TestPreflightNamesRawSocket(t *testing.T) {
	ctx := context.Background()
	spec := specFor(tunnel.ModeRelay, tunnel.SideA)
	spec.Params[tunnel.ParamConfigDir] = t.TempDir()

	probs := Adapter{}.Preflight(ctx, spec)
	raw := findProblem(probs, "raw_socket")

	switch {
	case runtime.GOOS != "linux":
		// The helper cannot probe AF_INET/SOCK_RAW here; it must say so by
		// name rather than report ready.
		if raw == nil {
			t.Fatalf("Preflight must report the raw_socket requirement on %s, got %+v", runtime.GOOS, probs)
		}
		if _, err := (Adapter{}).Start(ctx, spec, tunnel.Ports{Listen: 20123, Control: 20124}); err == nil {
			t.Fatal("Start must refuse on a host with no raw socket")
		} else if !strings.Contains(err.Error(), "raw_socket") {
			t.Fatalf("Start's refusal must carry the preflight problem, got: %v", err)
		} else if strings.Contains(err.Error(), "exec:") || strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("Start must refuse BEFORE exec, not report the tool's own error: %v", err)
		}
	case os.Geteuid() != 0:
		if raw == nil {
			t.Fatalf("Preflight must report raw_socket as a non-root user, got %+v", probs)
		}
		if !strings.Contains(raw.Fix, "CAP_NET_RAW") && !strings.Contains(raw.Fix, "root") {
			t.Fatalf("the fix must name the grant to give, got %q", raw.Fix)
		}
		_, err := Adapter{}.Start(ctx, spec, tunnel.Ports{Listen: 20123, Control: 20124})
		if err == nil {
			t.Fatal("Start must refuse without a raw socket")
		}
		if !strings.Contains(err.Error(), "raw_socket") && !strings.Contains(err.Error(), "CAP_NET_RAW") {
			t.Fatalf("Start's refusal must name the missing grant, got: %v", err)
		}
	default:
		// root on Linux: the requirement is met, so it must NOT be reported
		// (a preflight that always complains is as useless as one that never
		// does). Start then proceeds to the binary, which is the next gate.
		if raw != nil {
			t.Fatalf("as root the raw socket is available; Preflight must not report it: %v", raw)
		}
	}
}

func findProblem(probs []tunnel.Problem, check string) *tunnel.Problem {
	for i := range probs {
		if probs[i].Check == check {
			return &probs[i]
		}
	}
	return nil
}

func specFor(mode string, side tunnel.Side) tunnel.Spec {
	return tunnel.Spec{
		TunnelID: "render-1",
		Tool:     Tool,
		Side:     side,
		Mode:     mode,
		Params: map[string]string{
			tunnel.ParamListenPort: "20123",
			ParamListenHost:        "0.0.0.0",
			ParamPeer:              "10.250.9.2:20456",
			ParamTarget:            "10.250.9.2:20789",
		},
		Secrets: map[string]string{SecretKey: "render-secret-value"},
		Enabled: true,
	}
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func randomHexBytes(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	return randomHexBytes(n)
}

func mustHex(t *testing.T, s string) int {
	t.Helper()
	v, err := strconv.ParseInt(s, 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	return int(v)
}
