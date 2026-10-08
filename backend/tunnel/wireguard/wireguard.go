// Package wireguard runs WireGuard as a Phase 3 site-to-site VPN tunnel
// (CONTRACT §2.4): one tunnel row, two tunnel-role nodes, one kernel
// interface per side, subnet-to-subnet traffic across whatever underlay
// already reaches between the two nodes.
//
// There is no child process to supervise: the wireguard kernel module does
// the work, so Start writes the key and config files (0600, under the
// framework's per-tunnel directory), drives `ip`/`wg` to create the
// interface, address, peer and routes, and Shutdown deletes them and asserts
// the absence. Install provenance: distro package `wireguard-tools`, version
// reported from `wg --version` at Start — no sha256 pin exists upstream
// (UPSTREAM.md: WireGuard has no GitHub release asset; §2.3 rule 2 forbids
// inventing one).
//
// Mode support: site-to-site is `mode = relay`; `reverse` has no meaning for
// a subnet tunnel and Render/Start refuse it (CONTRACT §2.0) rather than
// falling back to a default.
package wireguard

import (
	"context"
	"encoding/base64"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/pasarguard/node/backend/tunnel"
	nodeLogger "github.com/pasarguard/node/logger"
)

const (
	// Tool is the registered adapter name.
	Tool = "wireguard"
	// SecretPrivateKey is the unprefixed secret name (CONTRACT §2.4): one
	// name on the wire, each node process supplying its own side's key from
	// its own environment.
	SecretPrivateKey = "private_key"
	// moduleName is the in-tree kernel module §2.3 requires.
	moduleName = "wireguard"
)

// moduleCheck is the shared /proc/modules reader (preflight.go). A var only
// so the test can prove the absent-module branch without rmmod'ing a live
// host module; production never reassigns it.
var moduleCheck = tunnel.CheckKernelModule

func init() { tunnel.Register(Tool, Adapter{}) }

// Adapter implements tunnel.Adapter.
type Adapter struct{}

var _ tunnel.Adapter = Adapter{}

// Start brings this side's kernel interface up. It never puts key material on
// a command line or in a log line: the key goes to a 0600 file, `wg setconf`
// reads the file, and every refusal names the param that caused it.
func (Adapter) Start(_ context.Context, spec tunnel.Spec, ports tunnel.Ports) (tunnel.Handle, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if modeOf(spec) != tunnel.ModeRelay {
		return nil, fmt.Errorf("%w: wireguard supports mode=%s only (site-to-site, CONTRACT §2.4); got %q",
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
		return nil, fmt.Errorf("%w: wireguard needs the %s secret (declare it and set the environment variable on this node)",
			tunnel.ErrSecretUnresolved, SecretPrivateKey)
	}
	if strings.ContainsAny(key, "\n\r") {
		return nil, fmt.Errorf("wireguard: %s contains a line break", SecretPrivateKey)
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("wireguard: %s is not a base64 Curve25519 private key (32 bytes after decoding)", SecretPrivateKey)
	}

	dir := spec.Params[tunnel.ParamConfigDir]
	if dir == "" {
		return nil, fmt.Errorf("wireguard: %s is not set — the key and config files need the per-tunnel directory", tunnel.ParamConfigDir)
	}
	wgBin, err := exec.LookPath("wg")
	if err != nil {
		return nil, fmt.Errorf("wireguard: wg (wireguard-tools) not found on PATH — install the distro package: %w", err)
	}
	ipBin, err := exec.LookPath("ip")
	if err != nil {
		return nil, fmt.Errorf("wireguard: ip (iproute2) not found on PATH — install iproute2: %w", err)
	}

	h := &handle{
		spec:    spec.Clone(),
		ports:   ports,
		sp:      sp,
		key:     key,
		dir:     dir,
		ifname:  IfName(spec),
		wgBin:   wgBin,
		ipBin:   ipBin,
		version: wgVersion(wgBin),
		logs:    make(chan string, 1024),
		lines:   make(chan nodeLogger.LogLine, 1024),
	}
	if err := h.bringUp(); err != nil {
		return nil, err
	}
	h.startPoller()
	return h, nil
}

// wgVersion reports what `wg --version` says — the honest version string for
// a tool with no pin (§2.3 rule 2).
func wgVersion(bin string) string {
	out, err := exec.Command(bin, "--version").CombinedOutput()
	v := strings.TrimSpace(string(out))
	if err != nil || v == "" {
		return "wireguard-tools (version unknown)"
	}
	return v
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
			Detail: fmt.Sprintf("wireguard is only tested in mode=%s; %q has no passing subnet-to-subnet run", tunnel.ModeRelay, spec.Mode),
			Fix:    "use mode=relay, or a tool that implements mode=reverse",
		})
	} else if loaded, err := loadParams(spec); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error()})
	} else if err := loaded.validate(); err != nil {
		out = append(out, tunnel.Problem{Check: "params", Detail: err.Error(), Fix: "correct the named params key (CONTRACT §2.4)"})
	} else {
		sp, paramsOK = loaded, true
	}

	for _, bin := range []string{"wg", "ip"} {
		if _, err := exec.LookPath(bin); err != nil {
			out = append(out, tunnel.Problem{
				Check:  "binary",
				Detail: fmt.Sprintf("%s is not on PATH", bin),
				Fix:    "install the distro packages: apt install wireguard-tools iproute2",
			})
		}
	}
	out = append(out, moduleCheck(moduleName)...)
	out = append(out, tunnel.CheckCapability("net_admin")...)
	if paramsOK && sp.Netns != "" {
		out = append(out, checkNetns(sp.Netns)...)
	}
	return out
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
