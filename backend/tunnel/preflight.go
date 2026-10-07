package tunnel

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// Problem is one thing this host cannot do for this tool. An empty Preflight
// result means "ready"; a non-empty one is what the panel surfaces instead of
// a bare "failed to start" (scope test 9).
type Problem struct {
	// Check is the machine-readable name: "root", "raw_socket", "iptables",
	// "nft", "kernel_module", "capability", "binary", "mode", "params".
	Check string `json:"check"`
	// Detail says what is wrong on THIS host, in one sentence.
	Detail string `json:"detail"`
	// Fix is what the operator can do about it, when there is something.
	Fix string `json:"fix,omitempty"`
}

func (p Problem) String() string {
	if p.Fix == "" {
		return fmt.Sprintf("%s: %s", p.Check, p.Detail)
	}
	return fmt.Sprintf("%s: %s (fix: %s)", p.Check, p.Detail, p.Fix)
}

// A host check that cannot run here says so with a host-specific reason; it
// never silently reports "ready".
func unsupported(check, what string) Problem {
	return Problem{
		Check:  check,
		Detail: fmt.Sprintf("%s is not available on %s/%s", what, runtime.GOOS, runtime.GOARCH),
		Fix:    "run this tool on a Linux node, or drop the requirement",
	}
}

// CheckRoot reports whether the process runs as root/administrator. Needed by
// tools that bind privileged ports or touch raw sockets.
func CheckRoot() []Problem {
	if runtime.GOOS == "windows" {
		// euid is meaningless here; the real question is an elevated token,
		// which os.Geteuid does not answer. Say so rather than guess.
		return []Problem{unsupported("root", "the euid check")}
	}
	if os.Geteuid() != 0 {
		return []Problem{{
			Check:  "root",
			Detail: fmt.Sprintf("process runs as uid %d, not root", os.Geteuid()),
			Fix:    "start the node as root, or grant the capability the tool needs",
		}}
	}
	return nil
}

// CheckCapability reports whether the effective capability set (Linux
// /proc/self/status CapEff) includes the named bits, e.g. "net_admin".
// Names use the kernel's spelling without the CAP_ prefix.
func CheckCapability(names ...string) []Problem {
	if runtime.GOOS != "linux" {
		return []Problem{unsupported("capability", "the CapEff check")}
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return []Problem{{Check: "capability", Detail: fmt.Sprintf("cannot read /proc/self/status: %v", err)}}
	}
	var capEff uint64
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return []Problem{{Check: "capability", Detail: fmt.Sprintf("unparsable CapEff: %v", err)}}
		}
		capEff = v
	}
	var out []Problem
	for _, name := range names {
		bit, ok := capabilityBit(name)
		if !ok {
			out = append(out, Problem{Check: "capability", Detail: fmt.Sprintf("unknown capability %q", name)})
			continue
		}
		if capEff&(1<<bit) == 0 {
			out = append(out, Problem{
				Check:  "capability",
				Detail: fmt.Sprintf("CAP_%s is not effective", strings.ToUpper(name)),
				Fix:    fmt.Sprintf("setcap cap_%s=ep <node binary>, or run as root", strings.ToLower(name)),
			})
		}
	}
	return out
}

// capabilityBit is the kernel's capability number for the names Phase 3 tools
// ask for. Unknown names are reported as a Problem rather than skipped.
func capabilityBit(name string) (uint, bool) {
	switch strings.ToLower(strings.TrimPrefix(strings.ToUpper(name), "CAP_")) {
	case "net_raw":
		return 13, true
	case "net_admin":
		return 12, true
	case "net_bind_service":
		return 10, true
	case "sys_admin":
		return 21, true
	}
	return 0, false
}

// CheckRawSocket reports whether the process can open an AF_INET SOCK_RAW
// socket — the udp2raw / packet-level tools' hard requirement.
func CheckRawSocket() []Problem {
	if runtime.GOOS == "windows" {
		return []Problem{unsupported("raw_socket", "AF_INET/SOCK_RAW probing")}
	}
	if err := probeRawSocket(); err != nil {
		return []Problem{{
			Check:  "raw_socket",
			Detail: fmt.Sprintf("cannot open a raw socket: %v", err),
			Fix:    "run as root, or grant CAP_NET_RAW",
		}}
	}
	return nil
}

// CheckFirewallTooling reports whether iptables or nft is present, because a
// tool whose install path rewrites NAT rules cannot work without one.
func CheckFirewallTooling() []Problem {
	switch runtime.GOOS {
	case "linux":
	default:
		return []Problem{unsupported("iptables", "packet-filter tooling")}
	}
	for _, tool := range []string{"nft", "iptables"} {
		if p, err := exec.LookPath(tool); err == nil && p != "" {
			return nil
		}
	}
	return []Problem{{
		Check:  "iptables",
		Detail: "neither nft nor iptables is installed",
		Fix:    "install nftables or iptables",
	}}
}

// CheckKernelModule reports whether a module is loaded (listed in
// /proc/modules). It never claims ready on a host where the question cannot be
// asked.
func CheckKernelModule(name string) []Problem {
	if runtime.GOOS != "linux" {
		return []Problem{unsupported("kernel_module", "the /proc/modules check")}
	}
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return []Problem{{Check: "kernel_module", Detail: fmt.Sprintf("cannot read /proc/modules: %v", err)}}
	}
	for _, line := range strings.Split(string(data), "\n") {
		field := strings.Fields(line)
		if len(field) > 0 && field[0] == name {
			return nil
		}
	}
	return []Problem{{
		Check:  "kernel_module",
		Detail: fmt.Sprintf("kernel module %q is not loaded", name),
		Fix:    fmt.Sprintf("modprobe %s", name),
	}}
}

// CheckBinary is the preflight half of the install rule: it resolves the
// pinned executable and reports the pin problems it hits, as Preflight output
// rather than a start-time error.
func CheckBinary(tool string) []Problem {
	if _, ok := PinFor(tool); !ok {
		return nil // in-process tool, no pin: nothing to check
	}
	if _, err := ResolveBinary(tool, ""); err != nil {
		return []Problem{{Check: "binary", Detail: err.Error(), Fix: "run the bundle fetcher, or set TUNNEL_BUNDLE_DIR"}}
	}
	return nil
}
