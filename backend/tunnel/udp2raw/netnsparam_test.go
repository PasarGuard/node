package udp2raw

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pasarguard/node/backend/tunnel"
)

// TestNetnsParamsPlaceProcesses is the piece the panel→server E2E stands on:
// with `a_netns` / `b_netns` set, the ADAPTER's own Start puts each side's
// udp2raw inside that namespace (`ip netns exec`), the data plane runs there,
// and the host keeps no state — the namespaces are removed with everything
// they held. The round's safety rule (netns + veth, never the host) is what
// makes this a product feature rather than test plumbing.
func TestNetnsParamsPlaceProcesses(t *testing.T) {
	ctx := context.Background()

	// ---- stage: a namespace this host does not have is refused BEFORE Start
	missing := specFor(tunnel.ModeRelay, tunnel.SideA)
	missing.Params[tunnel.ParamConfigDir] = t.TempDir()
	missing.Params[ParamANetns] = "u2r-never-created"
	probs := (Adapter{}).Preflight(ctx, missing)
	prob := findProblem(probs, "netns")
	if prob == nil {
		t.Fatalf("Preflight must report the missing namespace, got %+v", probs)
	}
	if runtime.GOOS == "linux" {
		// The namespace does not exist here either, so the fix is the command
		// that creates it.
		if !strings.Contains(prob.Fix, "ip netns add u2r-never-created") {
			t.Fatalf("the fix must be the command that creates it, got %q", prob.Fix)
		}
	} else if prob.Fix == "" {
		t.Fatalf("every Problem must carry a fix, got %+v", prob)
	}
	if _, err := (Adapter{}).Start(ctx, missing, tunnel.Ports{Listen: 20123, Control: 20124}); err == nil {
		t.Fatal("Start must refuse a namespace that does not exist")
	} else if !strings.Contains(err.Error(), "u2r-never-created") {
		t.Fatalf("the refusal must name the namespace, got: %v", err)
	} else if runtime.GOOS == "linux" && !strings.Contains(err.Error(), "ip netns add") {
		t.Fatalf("the refusal must carry the fix, got: %v", err)
	} else if runtime.GOOS != "linux" && !strings.Contains(err.Error(), "netns") {
		t.Fatalf("the refusal must be the netns problem, got: %v", err)
	}

	// ---- stage: the params are argv-only — the rendered config is identical
	// with and without them, and byte-identical across two renders.
	placed := specFor(tunnel.ModeRelay, tunnel.SideA)
	placed.Params[ParamANetns] = "u2r-side-a"
	placed.Params[ParamBNetns] = "u2r-side-b"
	plain := specFor(tunnel.ModeRelay, tunnel.SideA)
	r1, err := (Adapter{}).Render(placed)
	if err != nil {
		t.Fatalf("render with netns params: %v", err)
	}
	r2, err := (Adapter{}).Render(placed)
	if err != nil {
		t.Fatalf("second render: %v", err)
	}
	r0, err := (Adapter{}).Render(plain)
	if err != nil {
		t.Fatalf("render without netns params: %v", err)
	}
	if r1 != r2 {
		t.Fatalf("render is not deterministic with netns params:\n%s\n---\n%s", r1, r2)
	}
	if r1 != r0 {
		t.Fatalf("a_netns/b_netns must not change the rendered config:\nwith:\n%s\nwithout:\n%s", r1, r0)
	}

	// ---- the namespace run itself: Linux, root, ip(8), pinned binary
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux netns: " + runtime.GOOS + " cannot create network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to create network namespaces (ip netns add)")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("requires ip(8) from iproute2: " + err.Error())
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("requires python3 for the UDP echo and the datagram sender: " + err.Error())
	}
	requireBinary(t)

	suffix := randomHexBytes(3)
	nsA, nsB := "u2n"+suffix+"a", "u2n"+suffix+"b"
	ifA, ifB := "w"+suffix+"a", "w"+suffix+"b" // <= 15 chars
	subnet := 1 + mustHex(t, suffix[0:2])%250
	ipA := fmt.Sprintf("10.253.%d.1", subnet)
	ipB := fmt.Sprintf("10.253.%d.2", subnet)

	hostRulesBefore := hostCommand(t, "iptables-save")
	hostForwardBefore := hostCommand(t, "sysctl", "-n", "net.ipv4.ip_forward")

	teardown := spawnNetns(t, nsA, nsB, ifA, ifB, ipA, ipB)

	alloc := tunnel.NewAllocator()
	key := randomHexBytes(16)
	plan := &netnsPlan{
		TempDir: t.TempDir(),
		IPA:     ipA,
		IPB:     ipB,
		PortsA:  alloc.AllocPair(),
		PortsB:  alloc.AllocPair(),
		Echo:    alloc.AllocPair().Listen,
		RawMode: "faketcp",
		ID:      "u2p-" + randomHexBytes(6),
	}
	echo := exec.Command("ip", "netns", "exec", nsB, "python3", "-u", "-c", echoSource(plan.Echo))
	if err := echo.Start(); err != nil {
		t.Fatalf("start the UDP echo inside %s: %v", nsB, err)
	}
	t.Cleanup(func() {
		_ = echo.Process.Kill()
		_, _ = echo.Process.Wait()
		teardown()
		out, _ := exec.Command("ip", "netns", "list").CombinedOutput()
		left := strings.TrimSpace(string(out))
		if strings.Contains(left, nsA) || strings.Contains(left, nsB) {
			t.Errorf("network namespaces left behind: %s", left)
		}
		if after := hostCommand(t, "iptables-save"); after != hostRulesBefore {
			t.Errorf("the HOST iptables ruleset changed\nbefore: %s\nafter:  %s", hostRulesBefore, after)
		}
		// The strongest form of "the data plane never touched the host": not
		// just unchanged, but never carrying a udp2raw chain at all.
		if after := hostCommand(t, "iptables-save"); strings.Contains(after, "udp2raw") {
			t.Errorf("udp2raw rules exist on the HOST after the run: %s", after)
		}
		if after := hostCommand(t, "sysctl", "-n", "net.ipv4.ip_forward"); after != hostForwardBefore {
			t.Errorf("host net.ipv4.ip_forward changed: %s -> %s", hostForwardBefore, after)
		}
	})

	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: filepath.Join(plan.TempDir, "mgr")})
	t.Cleanup(m.Shutdown)

	specA := sideSpec(plan, tunnel.SideA, plan.ID, key, "")
	specB := sideSpec(plan, tunnel.SideB, plan.ID, key, "")
	specA.Params[ParamANetns] = nsA
	specA.Params[ParamBNetns] = nsB
	specB.Params[ParamANetns] = nsA
	specB.Params[ParamBNetns] = nsB

	// Side b first: side a's readiness is a completed handshake, and the
	// server's raw listener — and its -a rule that stops the kernel from
	// answering udp2raw's forged SYN — has to be there before side a dials.
	if err := m.Start(ctx, specB, plan.PortsB); err != nil {
		t.Fatalf("start side b in %s: %v", nsB, err)
	}
	if err := m.Start(ctx, specA, plan.PortsA); err != nil {
		t.Fatalf("start side a in %s: %v", nsA, err)
	}

	// Both processes must be inside their namespaces — a udp2raw chain in the
	// namespace can only exist if the process that inserted it ran there.
	rulesA, err := exec.Command("ip", "netns", "exec", nsA, "iptables-save").CombinedOutput()
	if err != nil {
		t.Fatalf("iptables-save in %s: %v\n%s", nsA, err, rulesA)
	}
	if !strings.Contains(string(rulesA), "udp2raw") {
		t.Fatalf("no udp2raw rules inside %s — the process is not in the namespace:\n%s", nsA, rulesA)
	}
	hostRules := hostCommand(t, "iptables-save")
	if strings.Contains(hostRules, "udp2raw") {
		t.Fatalf("udp2raw rules leaked onto the HOST: %s", hostRules)
	}

	// A real UDP datagram, sent from INSIDE nsA (the host has no address on
	// this pair — by design), answered by the echo inside nsB through the
	// tunnel: sha256(payload) back, byte-for-byte.
	out, err := exec.Command("ip", "netns", "exec", nsA, "python3", "-u", "-c",
		senderSource(plan.PortsA.Listen)).CombinedOutput()
	if err != nil {
		t.Fatalf("datagrams through the namespaced tunnel: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "delivered 5 / 5") {
		t.Fatalf("the tunnel did not carry every datagram: %s", out)
	}
	t.Logf("a_netns=%s b_netns=%s: 5 UDP datagrams round-tripped; nsA rules carry udp2raw, host rules do not",
		nsA, nsB)

	// Stop both sides first, so udp2raw's own -a cleanup runs inside the
	// namespace before the namespace itself is destroyed.
	if err := m.Stop(plan.ID); err != nil && !errors.Is(err, tunnel.ErrNotRunning) {
		t.Fatalf("stop: %v", err)
	}
	if err := exec.Command("ip", "netns", "del", nsA).Run(); err != nil {
		t.Fatalf("delete %s: %v", nsA, err)
	}
	if err := exec.Command("ip", "netns", "del", nsB).Run(); err != nil {
		t.Fatalf("delete %s: %v", nsB, err)
	}
	left, _ := exec.Command("ip", "netns", "list").CombinedOutput()
	if strings.Contains(string(left), nsA) || strings.Contains(string(left), nsB) {
		t.Fatalf("namespaces still present after teardown: %s", left)
	}
	t.Logf("teardown: %s and %s gone, ip netns list is [ %s ]", nsA, nsB, strings.TrimSpace(string(left)))
}

// echoSource is the destination inside nsB: replies with sha256(payload), so
// a single wrong byte anywhere in the path is visible at the sender.
func echoSource(port int) string {
	return fmt.Sprintf(`import hashlib, socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", %d))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(hashlib.sha256(d).digest(), a)`, port)
}

// senderSource sends 5 datagrams from inside nsA and exits non-zero unless
// every reply is the destination's own sha256 of what it sent.
func senderSource(port int) string {
	return fmt.Sprintf(`import hashlib, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
ok = 0
for i in range(5):
    p = b"u2r-netns-" + bytes([i]) * 40
    s.sendto(p, ("127.0.0.1", %d))
    d, _ = s.recvfrom(256)
    ok += 1 if d == hashlib.sha256(p).digest() else 0
print("delivered", ok, "/ 5")
sys.exit(0 if ok == 5 else 1)`, port)
}
