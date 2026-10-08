// Package amnezia runs AmneziaWG as a Phase 3 site-to-site VPN tunnel
// (CONTRACT §2.4): one tunnel row, two tunnel-role nodes, one TUN interface
// per side, subnet-to-subnet traffic across whatever underlay already
// reaches between the two nodes.
//
// Userspace only (CONTRACT §2.3.1): the reference host has no kernel headers
// for 6.8.0-35-generic, so no amnezia-wg-kmod is built or loaded and the
// in-tree `wireguard` module is untouched. The work is done by the
// amneziawg-go daemon — a TUN device plus a control socket — and this package
// drives it over that socket with amneziawg-go's own uapi text protocol.
// The `awg` CLI (amnezia-wg-tools, GPL-2.0) is neither required nor linked;
// this repo is MIT (§2.3.1).
//
// Install provenance (§2.3 rule 2): there is no upstream binary asset and no
// published sha256, so there is no hash pin to invent. The pin is the source
// tag: build `amnezia-vpn/amneziawg-go` at tag v3.1.20260828 (commit
// b5928efb6ca19f0153958460c3d141f04abc5c2e) with `make`, put the binary on
// PATH, and Preflight refuses anything whose first version line is not
// "amneziawg-go v3.1.20260828".
//
// Mode support: site-to-site is `mode = relay`; `reverse` has no meaning for
// a subnet tunnel and Render/Start refuse it (CONTRACT §2.0) rather than
// falling back to a default.
package amnezia

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/pasarguard/node/backend/tunnel"
	nodeLogger "github.com/pasarguard/node/logger"
)

const (
	// Tool is the registered adapter name.
	Tool = "amnezia"
	// SecretPrivateKey is the unprefixed secret name (CONTRACT §2.4): one
	// name on the wire, each node process supplying its own side's key from
	// its own environment.
	SecretPrivateKey = "private_key"
	// BinaryName is what Preflight resolves: the amnezia daemon on PATH, or
	// the path the node hands us in pg_binary_path.
	BinaryName = "amneziawg-go"
	// ExpectedVersion is the version-string pin (§2.3 rule 2). The first line
	// of `amneziawg-go --version` must equal it exactly; anything else is
	// refused with the build provenance in the Fix.
	ExpectedVersion = "amneziawg-go v3.1.20260828"
	// SourcePin names the tag the expected version was built from.
	SourcePin = "amnezia-vpn/amneziawg-go tag v3.1.20260828 (commit b5928efb6ca19f0153958460c3d141f04abc5c2e)"
)

// buildFix is the operator's recipe. It is the same sentence Preflight's
// binary Problem carries and the doc's install section.
const buildFix = "build it from source: git clone --branch v3.1.20260828 https://github.com/amnezia-vpn/amneziawg-go && cd amneziawg-go && git rev-parse HEAD  # must print b5928efb6ca19f0153958460c3d141f04abc5c2e && make && cp amneziawg-go /usr/local/bin/"

func init() { tunnel.Register(Tool, Adapter{}) }

// Adapter implements tunnel.Adapter.
type Adapter struct{}

var _ tunnel.Adapter = Adapter{}

// resolveBinary honours pg_binary_path first (the node may pin a path), then
// PATH. It returns the binary as given; the version check is what proves it is
// the pinned build.
func resolveBinary(spec tunnel.Spec) (string, error) {
	if p := strings.TrimSpace(spec.Params[tunnel.ParamBinaryPath]); p != "" {
		return p, nil
	}
	p, err := exec.LookPath(BinaryName)
	if err != nil {
		return "", fmt.Errorf("%s is not on PATH and no %s param was given: %w", BinaryName, tunnel.ParamBinaryPath, err)
	}
	return p, nil
}

// versionOf runs the binary's --version and returns its first line. This is
// the whole install check for a tool with no hash to pin (§2.3 rule 2).
func versionOf(bin string) (string, error) {
	out, err := exec.Command(bin, "--version").CombinedOutput()
	first, _, _ := strings.Cut(string(out), "\n")
	first = strings.TrimSpace(first)
	if err != nil {
		if first == "" {
			return "", fmt.Errorf("%s --version failed: %w", bin, err)
		}
		return first, nil // a binary that answers and still exits non-zero
	}
	if first == "" {
		return "", fmt.Errorf("%s --version printed nothing", bin)
	}
	return first, nil
}

// checkVersion is the pin, factored out so the portable suite can assert it
// without a real binary on the machine it runs on.
func checkVersion(got string) error {
	if got != ExpectedVersion {
		return fmt.Errorf("version string %q does not match the pin %q (%s)", got, ExpectedVersion, SourcePin)
	}
	return nil
}

// Start brings this side's userspace AmneziaWG up: the daemon, the uapi
// configuration, the interface, its address and its routes. Key material
// never appears on a command line or in a log line — it is sent over the
// daemon's control socket.
func (Adapter) Start(_ context.Context, spec tunnel.Spec, ports tunnel.Ports) (tunnel.Handle, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if modeOf(spec) != tunnel.ModeRelay {
		return nil, fmt.Errorf("%w: amnezia supports mode=%s only (site-to-site, CONTRACT §2.4); got %q",
			tunnel.ErrModeUnsupported, tunnel.ModeRelay, spec.Mode)
	}
	sp, err := loadParams(spec)
	if err != nil {
		return nil, err
	}
	if err := sp.validate(); err != nil {
		return nil, err
	}

	key := strings.TrimSpace(spec.Secrets[SecretPrivateKey])
	if key == "" {
		return nil, fmt.Errorf("%w: amnezia needs the %s secret (declare it and set the environment variable on this node)",
			tunnel.ErrSecretUnresolved, SecretPrivateKey)
	}
	if strings.ContainsAny(key, "\n\r") {
		return nil, fmt.Errorf("amnezia: %s contains a line break", SecretPrivateKey)
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("amnezia: %s is not a base64 Curve25519 private key (32 bytes after decoding)", SecretPrivateKey)
	}

	bin, err := resolveBinary(spec)
	if err != nil {
		return nil, fmt.Errorf("amnezia: %w (install: %s)", err, buildFix)
	}
	got, err := versionOf(bin)
	if err != nil {
		return nil, fmt.Errorf("amnezia: cannot run %s: %w (install: %s)", bin, err, buildFix)
	}
	if err := checkVersion(got); err != nil {
		return nil, fmt.Errorf("amnezia: %s: %w (install: %s)", bin, err, buildFix)
	}
	ipBin, err := exec.LookPath("ip")
	if err != nil {
		return nil, fmt.Errorf("amnezia: ip (iproute2) not found on PATH — install iproute2: %w", err)
	}

	h := &handle{
		spec:    spec.Clone(),
		ports:   ports,
		sp:      sp,
		key:     key,
		bin:     bin,
		ipBin:   ipBin,
		ifname:  IfName(spec),
		version: got,
		logs:    make(chan string, 1024),
		lines:   make(chan nodeLogger.LogLine, 1024),
	}
	if err := h.bringUp(); err != nil {
		return nil, err
	}
	h.startPoller()
	return h, nil
}

// Preflight reports what this host cannot do for this spec. Empty means ready.
// Every problem carries a fix; nothing here starts a process or mutates the
// host (CONTRACT §2.3).
func (Adapter) Preflight(_ context.Context, spec tunnel.Spec) []tunnel.Problem {
	var out []tunnel.Problem

	var sp sideParams
	paramsOK := false
	if err := spec.Validate(); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error()})
	} else if modeOf(spec) != tunnel.ModeRelay {
		out = append(out, tunnel.Problem{
			Check:  "mode",
			Detail: fmt.Sprintf("amnezia is only tested in mode=%s; %q has no passing subnet-to-subnet run", tunnel.ModeRelay, spec.Mode),
			Fix:    "use mode=relay, or a tool that implements mode=reverse",
		})
	} else if loaded, err := loadParams(spec); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error()})
	} else if err := loaded.validate(); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error(), Fix: "correct the named params key (CONTRACT §2.4)"})
	} else {
		sp, paramsOK = loaded, true
	}

	if bin, err := resolveBinary(spec); err != nil {
		out = append(out, tunnel.Problem{
			Check:  "binary",
			Detail: fmt.Sprintf("%s is not on PATH and no %s param was given", BinaryName, tunnel.ParamBinaryPath),
			Fix:    buildFix,
		})
	} else if got, err := versionOf(bin); err != nil {
		out = append(out, tunnel.Problem{
			Check:  "binary",
			Detail: fmt.Sprintf("%s does not answer --version: %v", bin, err),
			Fix:    buildFix,
		})
	} else if err := checkVersion(got); err != nil {
		out = append(out, tunnel.Problem{
			Check:  "binary",
			Detail: fmt.Sprintf("%s: %v", bin, err),
			Fix:    buildFix,
		})
	}

	if _, err := exec.LookPath("ip"); err != nil {
		out = append(out, tunnel.Problem{
			Check:  "binary",
			Detail: "ip is not on PATH",
			Fix:    "install iproute2",
		})
	}
	out = append(out, checkTUNDevice()...)
	out = append(out, tunnel.CheckCapability("net_admin")...)
	if paramsOK && sp.Netns != "" {
		out = append(out, checkNetns(sp.Netns)...)
	}
	return out
}

// checkTUNDevice is CONTRACT §2.3's requirement for every wireguard-go-family
// userspace daemon: /dev/net/tun must exist. Written here rather than in the
// framework because the framework's preflight helpers have no TUN check.
// tunDevice is a var only so the test can prove the absent-device branch
// without removing the host's real node; production never reassigns it.
var tunDevice = "/dev/net/tun"

func checkTUNDevice() []tunnel.Problem {
	if runtime.GOOS != "linux" {
		return []tunnel.Problem{{
			Check:  "tun",
			Detail: fmt.Sprintf("%s is not available on %s/%s", tunDevice, runtime.GOOS, runtime.GOARCH),
			Fix:    "run this tunnel on a Linux node (CONTRACT §2.3.1, userspace AmneziaWG)",
		}}
	}
	st, err := os.Stat(tunDevice)
	if err != nil {
		return []tunnel.Problem{{
			Check:  "tun",
			Detail: fmt.Sprintf("%s is not present: %v", tunDevice, err),
			Fix:    "load the tun module: modprobe tun (the reference host ships it as crw-rw-rw-)",
		}}
	}
	if st.Mode()&os.ModeDevice == 0 {
		return []tunnel.Problem{{
			Check:  "tun",
			Detail: fmt.Sprintf("%s exists but is not a character device", tunDevice),
			Fix:    "recreate it: modprobe tun",
		}}
	}
	return nil
}

// checkNetns reports a network namespace the spec asks for but this host does
// not have — named as a Problem instead of failing later at exec (§2.4).
func checkNetns(ns string) []tunnel.Problem {
	if runtime.GOOS != "linux" {
		return []tunnel.Problem{{
			Check:  "netns",
			Detail: fmt.Sprintf("network namespace %q cannot be used on %s/%s", ns, runtime.GOOS, runtime.GOARCH),
			Fix:    "run this tunnel on a Linux node (CONTRACT §2.3)",
		}}
	}
	ipBin, err := exec.LookPath("ip")
	if err != nil {
		return []tunnel.Problem{{
			Check:  "netns",
			Detail: fmt.Sprintf("cannot verify namespace %q: ip is not on PATH", ns),
			Fix:    "install iproute2",
		}}
	}
	out, err := exec.Command(ipBin, "netns", "list").Output()
	if err != nil {
		return []tunnel.Problem{{
			Check:  "netns",
			Detail: fmt.Sprintf("cannot list network namespaces to verify %q: %v", ns, err),
			Fix:    "run the node as root, or drop the netns param",
		}}
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == ns {
			return nil
		}
	}
	return []tunnel.Problem{{
		Check:  "netns",
		Detail: fmt.Sprintf("network namespace %q does not exist on this host", ns),
		Fix:    fmt.Sprintf("create it first: ip netns add %s, or leave <side>_netns empty to use the node's own namespace", ns),
	}}
}
