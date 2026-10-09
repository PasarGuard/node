package amnezia

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
)

// The netns half of the suite: every claim CONTRACT §2.4 and the 2a brief make
// about site-to-site — handshake, subnet-to-subnet traffic in both directions,
// teardown absence, restart from the same Spec, unauthorised-key refusal, log
// isolation, and the obfuscation pair — is asserted inside network namespaces
// joined by veth pairs. The host's default route, host iptables and host
// ip_forward are never touched (§2.3 rule 1); forwarding is flipped inside the
// namespace, where it is namespaced state.
//
// Windows cannot create network namespaces; the skip below says exactly that,
// and the Linux run must be zero-skip, zero-fail.

// requireNetns is the gate every namespace test calls first.
func requireNetns(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("amnezia site-to-site runs in network namespaces; %s cannot create them (CONTRACT §2.3.1) — run this test on the Linux node", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		t.Skip("amnezia site-to-site needs root for ip netns add and CAP_NET_ADMIN — run this test as root on the Linux node")
	}
	for _, bin := range []string{"ip", "ping"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s is not on PATH on this host — install it (iproute2 / iputils-ping) and rerun on the Linux node", bin)
		}
	}
	// Preflight insists on the pinned version string, so the suite needs the
	// pinned binary on PATH too. The reference server builds it at
	// /root/awg-build; a local build is found on PATH or via $AWG_BINARY.
	if _, err := exec.LookPath(BinaryName); err != nil {
		for _, cand := range []string{os.Getenv("AWG_BINARY"), "/root/awg-build/" + BinaryName, "/usr/local/bin/" + BinaryName} {
			if cand == "" {
				continue
			}
			if st, err := os.Stat(cand); err != nil || st.IsDir() {
				continue
			}
			d := t.TempDir()
			if err := os.Symlink(cand, filepath.Join(d, BinaryName)); err != nil {
				t.Skipf("cannot link %s onto PATH: %v", cand, err)
			}
			t.Setenv("PATH", d+string(os.PathListSeparator)+os.Getenv("PATH"))
			break
		}
	}
	if _, err := exec.LookPath(BinaryName); err != nil {
		t.Skipf("%s is not on PATH (tried $AWG_BINARY, /root/awg-build, /usr/local/bin) — build the pinned source: git clone --branch v3.1.20260828 https://github.com/amnezia-vpn/amneziawg-go && make — then rerun on the Linux node", BinaryName)
	}
}

// requireKernelWG gates the two negative controls that need an unmodified
// kernel WireGuard client. Userspace AmneziaWG itself never needs it
// (CONTRACT §2.3.1), so its absence is a named skip, not a suite failure.
func requireKernelWG(t *testing.T) {
	t.Helper()
	requireNetns(t)
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skipf("wg (wireguard-tools) is not on PATH — the kernel-WireGuard negative control needs it; install wireguard-tools")
	}
	if probs := tunnel.CheckKernelModule("wireguard"); len(probs) > 0 {
		t.Skipf("kernel module %q is not loaded: %s", "wireguard", probs[0].Detail)
	}
}

// ---------------------------------------------------------------------------
// command helpers

func runHost(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("host: ip %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// nsCmd runs name inside ns (via `ip netns exec`) and returns rc + output.
func nsCmd(ns, name string, args ...string) (int, string) {
	full := append([]string{"netns", "exec", ns, name}, args...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	rc := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else {
			rc = -1
		}
	}
	return rc, strings.TrimSpace(string(out))
}

func mustNsCmd(t *testing.T, ns, name string, args ...string) string {
	t.Helper()
	rc, out := nsCmd(ns, name, args...)
	if rc != 0 {
		t.Fatalf("%s in %s: %s: rc=%d\n%s", name, ns, strings.Join(args, " "), rc, out)
	}
	return out
}

// mustFailNsCmd requires the command to fail — the absence assertions.
func mustFailNsCmd(t *testing.T, what, ns, name string, args ...string) string {
	t.Helper()
	rc, out := nsCmd(ns, name, args...)
	if rc == 0 {
		t.Fatalf("%s: %s succeeded in %s, want failure: %s", what, name, ns, out)
	}
	return out
}

func randHex(t *testing.T, nBytes int) string {
	t.Helper()
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// ---------------------------------------------------------------------------
// topology: two router namespaces joined by an underlay veth, each router
// fronting a host namespace on its own LAN.
//
//	host LAN A 192.168.10.0/24          host LAN B 192.168.20.0/24
//	  nsHA .101 --- nsRA (gw .1)  awg ===  nsRB (gw .1) --- nsHB .201
//	                        underlay 10.66.0.0/24 (veth)

type topo struct {
	id string // the tunnel id under test

	nsRA, nsRB, nsHA, nsHB string
	vU, vL, vH             string // unique veth name stems (host-visible for a moment)

	tunA, tunB         string // 10.67.0.x (addresses, no mask)
	tunCIDRA, tunCIDRB string
	underA, underB     string // underlay addresses, no mask
	lanA, lanB         string // LAN CIDRs
	gwA, gwB           string // LAN gateway addresses
	hostA, hostB       string // the "hosts" that must reach each other
}

func newTopo(t *testing.T) *topo {
	t.Helper()
	requireNetns(t)

	sfx := randHex(t, 3)
	tp := &topo{
		id:       "pga" + randHex(t, 5),
		nsRA:     "pgaa" + sfx,
		nsRB:     "pgab" + sfx,
		nsHA:     "pgah" + sfx,
		nsHB:     "pgai" + sfx,
		vU:       "vua" + sfx,
		vL:       "vla" + sfx,
		vH:       "vha" + sfx,
		tunA:     "10.68.0.1",
		tunB:     "10.68.0.2",
		tunCIDRA: "10.68.0.1/24",
		tunCIDRB: "10.68.0.2/24",
		underA:   "10.66.1.1",
		underB:   "10.66.1.2",
		lanA:     "192.168.30.0/24",
		lanB:     "192.168.40.0/24",
		gwA:      "192.168.30.1",
		gwB:      "192.168.40.1",
		hostA:    "192.168.30.101",
		hostB:    "192.168.40.101",
	}

	// Registered first so it runs last (LIFO): verify nothing leaked.
	t.Cleanup(func() {
		listed, err := exec.Command("ip", "netns", "list").CombinedOutput()
		if err != nil {
			t.Errorf("ip netns list after cleanup: %v (%s)", err, listed)
		}
		for _, line := range strings.Split(string(listed), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			for _, ns := range []string{tp.nsRA, tp.nsRB, tp.nsHA, tp.nsHB} {
				if fields[0] == ns {
					t.Errorf("namespace %s survived cleanup", ns)
				}
			}
		}
		if v := hostIPForward(); v != "0" {
			t.Errorf("host ip_forward = %s, want 0 — the tests only flip it inside a namespace", v)
		}
	})

	for _, ns := range []string{tp.nsRA, tp.nsRB, tp.nsHA, tp.nsHB} {
		runHost(t, "netns", "add", ns)
		ns := ns
		t.Cleanup(func() {
			_ = exec.Command("ip", "netns", "del", ns).Run()
		})
	}

	// Underlay between the two routers.
	runHost(t, "link", "add", tp.vU+"a", "type", "veth", "peer", "name", tp.vU+"b")
	runHost(t, "link", "set", tp.vU+"a", "netns", tp.nsRA)
	runHost(t, "link", "set", tp.vU+"b", "netns", tp.nsRB)

	// LAN A: router -- host.
	runHost(t, "link", "add", tp.vL+"a", "type", "veth", "peer", "name", tp.vH+"a")
	runHost(t, "link", "set", tp.vL+"a", "netns", tp.nsRA)
	runHost(t, "link", "set", tp.vH+"a", "netns", tp.nsHA)

	// LAN B: router -- host.
	runHost(t, "link", "add", tp.vL+"b", "type", "veth", "peer", "name", tp.vH+"b")
	runHost(t, "link", "set", tp.vL+"b", "netns", tp.nsRB)
	runHost(t, "link", "set", tp.vH+"b", "netns", tp.nsHB)

	// Router A.
	mustNsCmd(t, tp.nsRA, "ip", "addr", "add", tp.underA+"/24", "dev", tp.vU+"a")
	mustNsCmd(t, tp.nsRA, "ip", "link", "set", tp.vU+"a", "up")
	mustNsCmd(t, tp.nsRA, "ip", "addr", "add", tp.gwA+"/24", "dev", tp.vL+"a")
	mustNsCmd(t, tp.nsRA, "ip", "link", "set", tp.vL+"a", "up")
	mustNsCmd(t, tp.nsRA, "ip", "link", "set", "lo", "up")
	mustNsCmd(t, tp.nsRA, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")

	// Router B.
	mustNsCmd(t, tp.nsRB, "ip", "addr", "add", tp.underB+"/24", "dev", tp.vU+"b")
	mustNsCmd(t, tp.nsRB, "ip", "link", "set", tp.vU+"b", "up")
	mustNsCmd(t, tp.nsRB, "ip", "addr", "add", tp.gwB+"/24", "dev", tp.vL+"b")
	mustNsCmd(t, tp.nsRB, "ip", "link", "set", tp.vL+"b", "up")
	mustNsCmd(t, tp.nsRB, "ip", "link", "set", "lo", "up")
	mustNsCmd(t, tp.nsRB, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")

	// Host A.
	mustNsCmd(t, tp.nsHA, "ip", "addr", "add", tp.hostA+"/24", "dev", tp.vH+"a")
	mustNsCmd(t, tp.nsHA, "ip", "link", "set", tp.vH+"a", "up")
	mustNsCmd(t, tp.nsHA, "ip", "link", "set", "lo", "up")
	mustNsCmd(t, tp.nsHA, "ip", "route", "add", "default", "via", tp.gwA)

	// Host B.
	mustNsCmd(t, tp.nsHB, "ip", "addr", "add", tp.hostB+"/24", "dev", tp.vH+"b")
	mustNsCmd(t, tp.nsHB, "ip", "link", "set", tp.vH+"b", "up")
	mustNsCmd(t, tp.nsHB, "ip", "link", "set", "lo", "up")
	mustNsCmd(t, tp.nsHB, "ip", "route", "add", "default", "via", tp.gwB)

	// The underlay must work before anything else is claimed.
	if rc, out := nsCmd(tp.nsRA, "ping", "-c", "2", "-W", "2", tp.underB); rc != 0 {
		t.Fatalf("underlay ping %s -> %s failed (rc=%d): %s", tp.nsRA, tp.underB, rc, out)
	}
	return tp
}

func hostIPForward() string {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return "unreadable: " + err.Error()
	}
	return strings.TrimSpace(string(b))
}

// ---------------------------------------------------------------------------
// tunnel pair under test

type pairT struct {
	m              *tunnel.Manager
	tp             *topo
	portsA, portsB tunnel.Ports
	specA, specB   tunnel.Spec
}

func newTestManager(t *testing.T) *tunnel.Manager {
	t.Helper()
	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: t.TempDir()})
	t.Cleanup(m.Shutdown)
	return m
}

// genKeyPair runs `wg genkey`/`wg pubkey`. Keys are returned but never
// logged: the test prints commands and outputs, not key material.
func genKeyPair(t *testing.T) (priv, pub string) {
	t.Helper()
	out, err := exec.Command("wg", "genkey").CombinedOutput()
	if err != nil {
		t.Fatalf("wg genkey: %v (%s)", err, out)
	}
	priv = strings.TrimSpace(string(out))
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv + "\n")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wg pubkey: %v (%s)", err, out)
	}
	return priv, strings.TrimSpace(string(out))
}

// genKeyPairNoWG is the same key generation without wireguard-tools, so the
// userspace suite is not gated on the kernel tooling it does not use.
// crypto/ecdh's X25519 clamps the scalar exactly as curve25519 does, so the
// public key is what wg pubkey would print for those 32 bytes.
func genKeyPairNoWG(t *testing.T) (priv, pub string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ecdh X25519: %v", err)
	}
	enc := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	return enc(k.Bytes()), enc(k.PublicKey().Bytes())
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	return tunnel.NewAllocator().AllocPair().Listen
}

// startPair brings both sides up through the adapter, with the row's one
// params dict (both prefixes) handed to each side unchanged — exactly what
// render_tunnel_spec does (CONTRACT §2.4 row encoding). tweak may add keys
// (obfuscation) before anything starts.
func startPair(t *testing.T, m *tunnel.Manager, tp *topo, tweak func(map[string]string)) *pairT {
	t.Helper()
	portsA, portsB := m.Alloc().AllocPair(), m.Alloc().AllocPair()
	keyA, pubA := genKeyPairNoWG(t)
	keyB, pubB := genKeyPairNoWG(t)

	params := map[string]string{
		"a_address":            tp.tunCIDRA,
		"a_lan_cidr":           tp.lanA,
		"a_peer_endpoint":      tp.underB + ":" + strconv.Itoa(portsB.Listen),
		"a_peer_public_key":    pubB,
		"a_peer_allowed_cidrs": tp.tunB + "/32," + tp.lanB,
		"a_netns":              tp.nsRA,
		"b_address":            tp.tunCIDRB,
		"b_lan_cidr":           tp.lanB,
		"b_peer_endpoint":      tp.underA + ":" + strconv.Itoa(portsA.Listen),
		"b_peer_public_key":    pubA,
		"b_peer_allowed_cidrs": tp.tunA + "/32," + tp.lanA,
		"b_netns":              tp.nsRB,
	}
	if tweak != nil {
		tweak(params)
	}
	specA := tunnel.Spec{
		TunnelID: tp.id, Tool: Tool, Side: tunnel.SideA, Mode: tunnel.ModeRelay,
		Params: params, Secrets: map[string]string{SecretPrivateKey: keyA}, Enabled: true,
	}
	specB := tunnel.Spec{
		TunnelID: tp.id, Tool: Tool, Side: tunnel.SideB, Mode: tunnel.ModeRelay,
		Params: params, Secrets: map[string]string{SecretPrivateKey: keyB}, Enabled: true,
	}
	ctx := context.Background()
	if err := m.Start(ctx, specA, portsA); err != nil {
		t.Fatalf("start side a: %v", err)
	}
	if err := m.Start(ctx, specB, portsB); err != nil {
		t.Fatalf("start side b: %v", err)
	}
	t.Cleanup(func() {
		if err := m.Stop(tp.id); err != nil && err != tunnel.ErrNotRunning {
			t.Errorf("stop %s: %v", tp.id, err)
		}
	})
	return &pairT{m: m, tp: tp, portsA: portsA, portsB: portsB, specA: specA, specB: specB}
}

func (p *pairT) ifA() string { return IfName(p.specA) }
func (p *pairT) ifB() string { return IfName(p.specB) }

// ---------------------------------------------------------------------------
// assertions over the daemon's uapi socket (never `wg` — that is the
// negative control's tool, not ours)

// uapiHandshake reads this side's newest peer handshake timestamp over its
// control socket. 0 means "no handshake yet".
func uapiHandshake(ifname string) int64 {
	u, err := dialUAPI(ifname, time.Second)
	if err != nil {
		return -1
	}
	defer func() { _ = u.Close() }()
	lines, err := u.get()
	if err != nil {
		return -1
	}
	_, peers := parseGet(lines)
	var newest int64
	for _, p := range peers {
		if p.LastHandshake > newest {
			newest = p.LastHandshake
		}
	}
	return newest
}

// waitHandshake polls this side's uapi socket until a peer reports a
// non-zero handshake timestamp, within a bounded budget.
func waitHandshake(t *testing.T, ifname string, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	last := int64(-2)
	for time.Now().Before(deadline) {
		last = uapiHandshake(ifname)
		if last > 0 {
			t.Logf("handshake ok on %s: last_handshake_time_sec=%d", ifname, last)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("no handshake within %s on %s (last uapi read: %d; -1 = socket unreachable)", budget, ifname, last)
}

// requireNoHandshake is the negative-control assertion: for the whole budget
// the timestamp must never leave 0.
func requireNoHandshake(t *testing.T, label string, read func() int64, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for i := 0; time.Now().Before(deadline); i++ {
		if v := read(); v > 0 {
			t.Fatalf("%s: handshake completed at sample %d after %s: last_handshake_time_sec=%d", label, i, time.Since(deadline), v)
		}
		time.Sleep(time.Second)
	}
	t.Logf("%s: no handshake for %s", label, budget)
}

// pingOnce returns rc and output; it never fails the test by itself.
func pingOnce(ns string, args ...string) (int, string) {
	return nsCmd(ns, "ping", args...)
}

// pingUntilOK retries until the destination answers — the first attempt is
// also what kicks the handshake initiation (a handshake only starts when a
// packet wants to go through).
func pingUntilOK(t *testing.T, ns, dst string, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	lastRC, lastOut := 1, ""
	for time.Now().Before(deadline) {
		lastRC, lastOut = pingOnce(ns, "-c", "1", "-W", "1", dst)
		if lastRC == 0 {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("ping %s in %s never succeeded within %s (rc=%d): %s", dst, ns, budget, lastRC, lastOut)
}

// mustPing is the assertion form: two packets, output logged so the raw test
// log carries the real receipt.
func mustPing(t *testing.T, ns, dst string) {
	t.Helper()
	rc, out := pingOnce(ns, "-c", "2", "-W", "2", dst)
	if rc != 0 {
		t.Fatalf("ping -c 2 %s in %s failed (rc=%d):\n%s", dst, ns, rc, out)
	}
	t.Logf("ping %s in %s:\n%s", dst, ns, out)
}

// mustNotPing is the negative assertion: the payload must not arrive.
func mustNotPing(t *testing.T, what, ns, dst string) {
	t.Helper()
	rc, out := pingOnce(ns, "-c", "2", "-W", "2", dst)
	if rc == 0 {
		t.Fatalf("%s: ping %s in %s succeeded, want failure:\n%s", what, dst, ns, out)
	}
	t.Logf("%s: ping %s in %s rc=%d (payload did not arrive):\n%s", what, dst, ns, rc, out)
}

// waitStats polls until both sides count bytes in both directions. On failure
// it dumps the daemon's own counters so the log shows whether they moved.
func waitStats(t *testing.T, p *pairT, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		list := p.m.List()
		ok := len(list) >= 2
		for _, st := range list {
			if st.BytesUp == 0 || st.BytesDown == 0 {
				ok = false
			}
		}
		if ok {
			for _, st := range list {
				t.Logf("stats %s side %s: up=%d down=%d state=%s version=%q",
					st.TunnelID, st.Side, st.BytesUp, st.BytesDown, st.State, st.Version)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, ifn := range []string{p.ifA(), p.ifB()} {
		t.Logf("uapi counters on %s: handshake=%d", ifn, uapiHandshake(ifn))
	}
	t.Fatalf("stats never counted both directions within %s: %+v", budget, p.m.List())
}

// ---------------------------------------------------------------------------
// the claims

// TestTwoNetnsHandshake: both sides up in their own namespace, preflight
// clean on this host, and the daemon reports a non-zero handshake within a
// bounded poll (brief item 1).
func TestTwoNetnsHandshake(t *testing.T) {
	tp := newTopo(t)
	m := newTestManager(t)
	pair := startPair(t, m, tp, nil)

	if probs := (Adapter{}).Preflight(context.Background(), pair.specA); len(probs) > 0 {
		t.Fatalf("preflight for a valid spec on this host is not empty: %v", probs)
	}

	// One packet to kick the handshake initiation, then the bounded poll.
	_, _ = pingOnce(tp.nsRA, "-c", "1", "-W", "2", tp.tunB)
	waitHandshake(t, pair.ifA(), 15*time.Second)
	waitHandshake(t, pair.ifB(), 15*time.Second)

	mustPing(t, tp.nsRA, tp.tunB)
	mustPing(t, tp.nsRB, tp.tunA)
	t.Logf("host ip_forward still %s (only namespace-local forwarding was flipped)", hostIPForward())
}

// TestSiteToSiteSubnetTraffic: a host in LAN A reaches a host in LAN B
// through the tunnel and back — subnet-to-subnet, both directions, not two
// pings between tunnel addresses (brief item 1's real claim).
func TestSiteToSiteSubnetTraffic(t *testing.T) {
	tp := newTopo(t)
	m := newTestManager(t)
	pair := startPair(t, m, tp, nil)
	t.Logf("tunnel %s: interfaces %s (in %s) and %s (in %s)", tp.id, pair.ifA(), tp.nsRA, pair.ifB(), tp.nsRB)

	pingUntilOK(t, tp.nsHA, tp.hostB, 20*time.Second)
	mustPing(t, tp.nsHA, tp.hostB) // LAN A host -> LAN B host
	mustPing(t, tp.nsHB, tp.hostA) // LAN B host -> LAN A host (the way back)
	waitStats(t, pair, 10*time.Second)
}

// TestStatsCountTheSendingSideAsUp: the tx=up / rx=down fold in Stats is
// proven by traffic, not assumed — a one-way 20x1000-byte UDP blast from
// LAN A to a closed port on LAN B must land in side a's Up and side b's Down.
// The mirrored fold fails both assertions by ~40KB.
func TestStatsCountTheSendingSideAsUp(t *testing.T) {
	tp := newTopo(t)
	m := newTestManager(t)
	_ = startPair(t, m, tp, nil)
	pingUntilOK(t, tp.nsHA, tp.hostB, 20*time.Second)

	blast := "for i in $(seq 1 20); do head -c 1000 /dev/zero > /dev/udp/" + tp.hostB + "/9999; done"
	rc, out := nsCmd(tp.nsHA, "bash", "-c", blast)
	t.Logf("one-way blast %s -> %s:9999 (20x1000B): rc=%d %s", tp.hostA, tp.hostB, rc, oneLine(out))
	if rc != 0 {
		t.Fatalf("blast did not run (no direction proof without it): rc=%d %s", rc, oneLine(out))
	}

	var a, b tunnel.Status
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		a, b = tunnel.Status{}, tunnel.Status{}
		for _, st := range m.List() {
			if st.Side == "a" {
				a = st
			} else {
				b = st
			}
		}
		if int64(a.BytesUp)-int64(a.BytesDown) > 10000 && int64(b.BytesDown)-int64(b.BytesUp) > 10000 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("side a: up=%d down=%d; side b: up=%d down=%d", a.BytesUp, a.BytesDown, b.BytesUp, b.BytesDown)
	if d := int64(a.BytesUp) - int64(a.BytesDown); d < 10000 {
		t.Fatalf("side a sent the blast but up-down = %d (<10000): tx is not counted as up (up=%d down=%d)",
			d, a.BytesUp, a.BytesDown)
	}
	if d := int64(b.BytesDown) - int64(b.BytesUp); d < 10000 {
		t.Fatalf("side b received the blast but down-up = %d (<10000): rx is not counted as down (up=%d down=%d)",
			d, b.BytesUp, b.BytesDown)
	}
}

// TestRestartSameSpec: stop, prove interface/address/routes are gone, re-Render
// byte-identically, start again from the same Spec, traffic flows (brief
// item 2).
func TestRestartSameSpec(t *testing.T) {
	tp := newTopo(t)
	m := newTestManager(t)
	pair := startPair(t, m, tp, nil)

	renderA1, err := Adapter{}.Render(pair.specA)
	if err != nil {
		t.Fatalf("render before stop: %v", err)
	}
	renderB1, err := Adapter{}.Render(pair.specB)
	if err != nil {
		t.Fatalf("render before stop: %v", err)
	}

	pingUntilOK(t, tp.nsHA, tp.hostB, 20*time.Second)

	if err := m.Stop(tp.id); err != nil {
		t.Fatalf("stop: %v", err)
	}
	assertAbsence(t, tp, pair)

	renderA2, err := Adapter{}.Render(pair.specA)
	if err != nil {
		t.Fatalf("render after stop: %v", err)
	}
	renderB2, err := Adapter{}.Render(pair.specB)
	if err != nil {
		t.Fatalf("render after stop: %v", err)
	}
	if renderA1 != renderA2 || renderB1 != renderB2 {
		t.Fatalf("Render drifted across a stop:\nA before:\n%s\nA after:\n%s\nB before:\n%s\nB after:\n%s",
			renderA1, renderA2, renderB1, renderB2)
	}
	t.Logf("re-render byte-identical after stop (interface line: %s)", IfName(pair.specA))

	ctx := context.Background()
	if err := m.Start(ctx, pair.specA, pair.portsA); err != nil {
		t.Fatalf("restart side a: %v", err)
	}
	if err := m.Start(ctx, pair.specB, pair.portsB); err != nil {
		t.Fatalf("restart side b: %v", err)
	}
	pingUntilOK(t, tp.nsHA, tp.hostB, 20*time.Second)
	mustPing(t, tp.nsHB, tp.hostA)
	waitStats(t, pair, 10*time.Second)
}

// assertAbsence is the leak check: no interface, no address, no route via
// the interface — a leaked route outlives the tunnel (brief item 2).
func assertAbsence(t *testing.T, tp *topo, p *pairT) {
	t.Helper()
	for _, side := range []struct {
		ns, ifname, tunAddr string
	}{
		{tp.nsRA, p.ifA(), tp.tunA},
		{tp.nsRB, p.ifB(), tp.tunB},
	} {
		out := mustFailNsCmd(t, "interface must be gone", side.ns, "ip", "link", "show", side.ifname)
		t.Logf("absent in %s: ip link show %s -> rc!=0 (%s)", side.ns, side.ifname, oneLine(out))

		routes := mustNsCmd(t, side.ns, "ip", "route", "show")
		for _, line := range strings.Split(routes, "\n") {
			if strings.Contains(line, "dev "+side.ifname) {
				t.Errorf("route via %s survived teardown in %s: %s", side.ifname, side.ns, line)
			}
		}
		addrs := mustNsCmd(t, side.ns, "ip", "addr", "show")
		if strings.Contains(addrs, side.tunAddr+"/") {
			t.Errorf("tunnel address %s still configured in %s after teardown", side.tunAddr, side.ns)
		}
		if _, err := os.Stat(sockPath(side.ifname)); err == nil {
			t.Errorf("uapi socket %s survived teardown", sockPath(side.ifname))
		}
	}
}

// TestUnauthorisedKeyNeverHandshakes: a third party presenting its own key —
// which nobody authorised — must complete no handshake and pass no traffic,
// and the authorised tunnel must carry on (brief item 3).
func TestUnauthorisedKeyNeverHandshakes(t *testing.T) {
	requireKernelWG(t)
	tp := newTopo(t)
	m := newTestManager(t)
	pair := startPair(t, m, tp, nil)
	pingUntilOK(t, tp.nsHA, tp.hostB, 20*time.Second) // authorised tunnel is live

	// Attacker namespace with its own link into router A's world.
	sfx := randHex(t, 3)
	nsC := "pgac" + sfx
	vC := "vca" + sfx
	runHost(t, "netns", "add", nsC)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", nsC).Run() })
	runHost(t, "link", "add", vC+"a", "type", "veth", "peer", "name", vC+"b")
	runHost(t, "link", "set", vC+"a", "netns", tp.nsRA)
	runHost(t, "link", "set", vC+"b", "netns", nsC)
	mustNsCmd(t, tp.nsRA, "ip", "addr", "add", "10.66.66.1/24", "dev", vC+"a")
	mustNsCmd(t, tp.nsRA, "ip", "link", "set", vC+"a", "up")
	mustNsCmd(t, nsC, "ip", "addr", "add", "10.66.66.2/24", "dev", vC+"b")
	mustNsCmd(t, nsC, "ip", "link", "set", vC+"b", "up")
	mustNsCmd(t, nsC, "ip", "link", "set", "lo", "up")

	// The attacker's own key — nobody on side A's side lists it.
	atkPriv, atkPub := genKeyPair(t)
	keyFile := filepath.Join(t.TempDir(), "attacker.key")
	if err := os.WriteFile(keyFile, []byte(atkPriv+"\n"), 0o600); err != nil {
		t.Fatalf("write attacker key: %v", err)
	}
	ifAtk := "wgat" + sfx[:4]
	atkPort := freeUDPPort(t)

	mustNsCmd(t, nsC, "ip", "link", "add", ifAtk, "type", "wireguard")
	mustNsCmd(t, nsC, "ip", "addr", "add", "10.68.0.9/24", "dev", ifAtk)
	mustNsCmd(t, nsC, "ip", "link", "set", ifAtk, "up")
	mustNsCmd(t, nsC, "wg", "set", ifAtk,
		"private-key", keyFile,
		"listen-port", strconv.Itoa(atkPort),
		"peer", pair.specA.Params["b_peer_public_key"],
		"endpoint", tp.underA+":"+strconv.Itoa(pair.portsA.Listen),
		"allowed-ips", tp.tunA+"/32,"+tp.lanA,
	)
	t.Logf("attacker up in %s presenting key %s — nobody authorised it", nsC, shortKey(atkPub))

	// The kernel client's own handshake timestamp must never leave 0.
	requireNoHandshake(t, "kernel-WG attacker (unauthorised key)", func() int64 {
		rc, hs := nsCmd(nsC, "wg", "show", ifAtk, "latest-handshakes")
		if rc != 0 {
			t.Fatalf("wg show latest-handshakes in attacker ns: rc=%d (%s)", rc, hs)
		}
		return parseWGHandshake(hs)
	}, 8*time.Second)

	// No traffic: the attacker's ping to the victim's tunnel address fails.
	mustNotPing(t, "unauthorised peer", nsC, tp.tunA)

	// The victim lists exactly the one authorised peer.
	if n := uapiPeerCount(pair.ifA()); n != 1 {
		t.Errorf("victim peer count = %d, want 1", n)
	}

	// The authorised tunnel is unaffected.
	mustPing(t, tp.nsHA, tp.hostB)
}

// uapiPeerCount is how many peers the daemon reports — replace_peers=true
// means the unauthorised key never becomes one.
func uapiPeerCount(ifname string) int {
	u, err := dialUAPI(ifname, time.Second)
	if err != nil {
		return -1
	}
	defer func() { _ = u.Close() }()
	lines, err := u.get()
	if err != nil {
		return -1
	}
	n := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "public_key=") {
			n++
		}
	}
	return n
}

// parseWGHandshake reads `wg show … latest-handshakes` lines
// ("<pubkey>\t<unix-seconds>") and returns the newest timestamp, 0 if none.
func parseWGHandshake(out string) int64 {
	var newest int64
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		tsField := fields[len(fields)-1]
		ts, err := strconv.ParseInt(tsField, 10, 64)
		if err == nil && ts > newest {
			newest = ts
		}
	}
	return newest
}

// TestLogsCarryOnlyThisTunnelID: every record in this tunnel's ring carries
// this tunnel_id and no line from the other tunnel appears under it (brief
// item 4).
func TestLogsCarryOnlyThisTunnelID(t *testing.T) {
	tp1 := newTopo(t)
	tp2 := newTopo(t)
	m := newTestManager(t)
	stream, cancel := m.Subscribe(256)
	defer cancel()

	p1 := startPair(t, m, tp1, nil)
	p2 := startPair(t, m, tp2, nil)

	pingUntilOK(t, tp1.nsHA, tp1.hostB, 20*time.Second)
	pingUntilOK(t, tp2.nsHA, tp2.hostB, 20*time.Second)

	recs1 := awaitRingRecords(t, m, tp1.id)
	recs2 := awaitRingRecords(t, m, tp2.id)

	other := map[string]string{
		tp1.id: tp2.id + "|" + p2.ifA() + "|" + p2.ifB() + "|" + tp2.nsRA + "|" + tp2.nsRB,
		tp2.id: tp1.id + "|" + p1.ifA() + "|" + p1.ifB() + "|" + tp1.nsRA + "|" + tp1.nsRB,
	}
	for _, tc := range []struct {
		id   string
		recs []tunnel.Record
	}{{tp1.id, recs1}, {tp2.id, recs2}} {
		for _, rec := range tc.recs {
			if rec.TunnelID != tc.id {
				t.Errorf("record in %s's ring carries tunnel_id %q", tc.id, rec.TunnelID)
			}
			if !strings.Contains(rec.Detail, tc.id) {
				t.Errorf("record detail does not mention its own tunnel_id %q: %q", tc.id, rec.Detail)
			}
			for _, needle := range strings.Split(other[tc.id], "|") {
				if needle != "" && strings.Contains(rec.Detail, needle) {
					t.Errorf("line from tunnel %s leaked into %s's ring: %q", needle, tc.id, rec.Detail)
				}
			}
		}
	}
	t.Logf("tunnel %s: %d records; tunnel %s: %d records; all tagged correctly", tp1.id, len(recs1), tp2.id, len(recs2))

	// The live stream must show both ids and nothing else.
	seen := map[string]bool{}
	deadline := time.After(10 * time.Second)
	for !seen[tp1.id] || !seen[tp2.id] {
		select {
		case rec := <-stream:
			if rec.TunnelID != tp1.id && rec.TunnelID != tp2.id {
				t.Fatalf("stream record carries foreign tunnel_id %q", rec.TunnelID)
			}
			seen[rec.TunnelID] = true
		case <-deadline:
			t.Fatalf("stream never showed both tunnel ids: %v", seen)
		}
	}
}

func awaitRingRecords(t *testing.T, m *tunnel.Manager, id string) []tunnel.Record {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if recs := m.Logs(id); len(recs) > 0 {
			return recs
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tunnel %s produced no log records", id)
	return nil
}

// ---------------------------------------------------------------------------
// the obfuscation pair (brief items 5 and 6)

// stdObfs is an explicit Jc/Jmin/Jmax/S1/S2/H1..H4 set — the parameter set
// every obfuscation claim in this file uses. It is deliberately different
// from the daemon's defaults so "honoured" means something.
var stdObfs = map[string]string{
	"jc": "4", "jmin": "40", "jmax": "70",
	"s1": "88", "s2": "128",
	"h1": "255", "h2": "191", "h3": "127", "h4": "63",
}

// withObfs writes a whole parameter set for both sides of the row.
func withObfs(a, b map[string]string) func(map[string]string) {
	return func(params map[string]string) {
		for k, v := range a {
			params["a_"+k] = v
		}
		for k, v := range b {
			params["b_"+k] = v
		}
	}
}

// obfsClone copies a parameter set so a caller can change one key.
func obfsClone(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// TestObfuscationHonoured: a pair configured with explicit Jc/Jmin/Jmax/S1/S2/
// H1..H4 completes a handshake and passes subnet-to-subnet traffic (brief
// item 5). The same test then restarts one side with a different H1 and Jc
// and proves the handshake dies (item 6's contrast, both halves in one log).
func TestObfuscationHonouredAndMismatchFails(t *testing.T) {
	t.Run("matching-set-handshakes", func(t *testing.T) {
		tp := newTopo(t)
		m := newTestManager(t)
		pair := startPair(t, m, tp, withObfs(stdObfs, stdObfs))
		t.Logf("both heads configured with %s", obfsSummary(stdObfs))

		pingUntilOK(t, tp.nsHA, tp.hostB, 20*time.Second)
		waitHandshake(t, pair.ifA(), 15*time.Second)
		waitHandshake(t, pair.ifB(), 15*time.Second)
		mustPing(t, tp.nsHA, tp.hostB)
		mustPing(t, tp.nsHB, tp.hostA)
		waitStats(t, pair, 10*time.Second)
	})

	t.Run("mismatched-set-no-handshake", func(t *testing.T) {
		tp := newTopo(t)
		m := newTestManager(t)
		// Same everything, one side different: side B's jc and h1. Nothing
		// else in the row changes.
		badB := obfsClone(stdObfs)
		badB["jc"] = "7"
		badB["h1"] = "200"
		pair := startPair(t, m, tp, withObfs(stdObfs, badB))
		t.Logf("side A: %s", obfsSummary(stdObfs))
		t.Logf("side B: %s  <- jc and h1 differ", obfsSummary(badB))

		// Give the initiation a chance: one packet, then a bounded poll.
		_, _ = pingOnce(tp.nsRA, "-c", "1", "-W", "2", tp.tunB)
		requireNoHandshake(t, "mismatched obfuscation (side A)", func() int64 { return uapiHandshake(pair.ifA()) }, 8*time.Second)
		requireNoHandshake(t, "mismatched obfuscation (side B)", func() int64 { return uapiHandshake(pair.ifB()) }, 3*time.Second)
		mustNotPing(t, "mismatched obfuscation", tp.nsRA, tp.tunB)
		mustNotPing(t, "mismatched obfuscation", tp.nsRB, tp.tunA)
	})
}

// TestKernelWGClientCannotHandshake: an unmodified kernel WireGuard client,
// holding the authorised key pair and pointing at the amnezia endpoint, must
// not complete a handshake against an obfuscated amneziawg head (brief item
// 7). The parameter set is stdObfs above (Jc=4 Jmin=40 Jmax=70 S1=88 S2=128
// H1=255 H2=191 H3=127 H4=63); the stock-default case is NOT asserted here.
func TestKernelWGClientCannotHandshake(t *testing.T) {
	requireKernelWG(t)
	tp := newTopo(t)
	m := newTestManager(t)

	// Side A is ours (obfuscated). Side B is a plain kernel wireguard
	// interface holding the very key side A authorises — so the only reason
	// a handshake can fail is the obfuscation.
	portsA, portsB := m.Alloc().AllocPair(), m.Alloc().AllocPair()
	keyA, _ := genKeyPairNoWG(t)
	keyB, pubB := genKeyPair(t)

	params := map[string]string{
		"a_address":            tp.tunCIDRA,
		"a_lan_cidr":           tp.lanA,
		"a_peer_endpoint":      tp.underB + ":" + strconv.Itoa(portsB.Listen),
		"a_peer_public_key":    pubB,
		"a_peer_allowed_cidrs": tp.tunB + "/32," + tp.lanB,
		"a_netns":              tp.nsRA,
		"b_address":            tp.tunCIDRB,
		"b_lan_cidr":           tp.lanB,
		"b_peer_endpoint":      tp.underA + ":" + strconv.Itoa(portsA.Listen),
		"b_peer_public_key":    "", // filled below: side A's public key
		"b_peer_allowed_cidrs": tp.tunA + "/32," + tp.lanA,
		"b_netns":              tp.nsRB,
	}
	pubA := mustPubOf(t, keyA)
	params["b_peer_public_key"] = pubA
	withObfs(stdObfs, nil)(params)

	specA := tunnel.Spec{
		TunnelID: tp.id, Tool: Tool, Side: tunnel.SideA, Mode: tunnel.ModeRelay,
		Params: params, Secrets: map[string]string{SecretPrivateKey: keyA}, Enabled: true,
	}
	if err := m.Start(context.Background(), specA, portsA); err != nil {
		t.Fatalf("start side a: %v", err)
	}
	t.Cleanup(func() {
		if err := m.Stop(tp.id); err != nil && err != tunnel.ErrNotRunning {
			t.Errorf("stop %s: %v", tp.id, err)
		}
	})

	// The unmodified kernel client, authorised on both sides of the key
	// exchange.
	keyFile := filepath.Join(t.TempDir(), "wgclient.key")
	if err := os.WriteFile(keyFile, []byte(keyB+"\n"), 0o600); err != nil {
		t.Fatalf("write kernel client key: %v", err)
	}
	ifB := "wgkb" + randHex(t, 2)
	mustNsCmd(t, tp.nsRB, "ip", "link", "add", ifB, "type", "wireguard")
	mustNsCmd(t, tp.nsRB, "ip", "addr", "add", tp.tunCIDRB, "dev", ifB)
	mustNsCmd(t, tp.nsRB, "ip", "link", "set", ifB, "up")
	mustNsCmd(t, tp.nsRB, "wg", "set", ifB,
		"private-key", keyFile,
		"listen-port", strconv.Itoa(portsB.Listen),
		"peer", pubA,
		"endpoint", tp.underA+":"+strconv.Itoa(portsA.Listen),
		"allowed-ips", tp.tunA+"/32,"+tp.lanA,
		"persistent-keepalive", "25",
	)
	t.Logf("kernel WG client %s in %s points at the obfuscated head (params %s)", ifB, tp.nsRB, obfsSummary(stdObfs))

	requireNoHandshake(t, "kernel-WG client vs obfuscated amneziawg head", func() int64 {
		rc, hs := nsCmd(tp.nsRB, "wg", "show", ifB, "latest-handshakes")
		if rc != 0 {
			t.Fatalf("wg show latest-handshakes: rc=%d (%s)", rc, hs)
		}
		return parseWGHandshake(hs)
	}, 10*time.Second)
	requireNoHandshake(t, "obfuscated head vs kernel-WG client", func() int64 {
		return uapiHandshake(IfName(specA))
	}, 3*time.Second)

	mustNotPing(t, "kernel client against obfuscated head", tp.nsRB, tp.tunA)
	mustNotPing(t, "obfuscated head against kernel client", tp.nsRA, tp.tunB)
}

// mustPubOf derives a public key from a private one with wg pubkey.
func mustPubOf(t *testing.T, priv string) string {
	t.Helper()
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wg pubkey: %v (%s)", err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestPreflightReadyOnThisHost: on a host that can do it, Preflight returns
// an empty slice for a valid spec — with and without a real namespace.
func TestPreflightReadyOnThisHost(t *testing.T) {
	requireNetns(t)
	sfx := randHex(t, 3)
	ns := "pgpf" + sfx
	runHost(t, "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })

	for _, tc := range []struct {
		name string
		spec tunnel.Spec
	}{
		{"own namespace", rowSpec(tunnel.SideA, nil)},
		{"explicit netns", rowSpec(tunnel.SideA, func(s *tunnel.Spec) { s.Params["a_netns"] = ns })},
	} {
		problems := (Adapter{}).Preflight(context.Background(), tc.spec)
		if len(problems) != 0 {
			t.Errorf("preflight for %s is not empty: %v", tc.name, problems)
		} else {
			t.Logf("preflight (%s): ready", tc.name)
		}
	}
}
