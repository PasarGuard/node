package udp2raw

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
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

const (
	// childEnv / planEnv select TestMain's child path: the four stages are
	// split across two processes, one inside each network namespace, because
	// a process belongs to exactly one namespace.
	childEnv = "U2R_CHILD"
	planEnv  = "U2R_PLAN"
)

// TestMain dispatches to a namespace child when the parent test spawned one,
// and runs the suite otherwise. Children never reach m.Run: their exit status
// is the stage result.
func TestMain(m *testing.M) {
	if role := os.Getenv(childEnv); role != "" {
		os.Exit(runChild(role))
	}
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// the four stages, inside two network namespaces joined by a veth pair

// TestFourPartRelayNetns runs all four stages in raw-mode faketcp (udp2raw's
// default). Windows skips with the host's own reason; the Linux run is
// zero-skip.
func TestFourPartRelayNetns(t *testing.T) { runNetnsStages(t, "faketcp", true) }

// TestRawModeEasyFakeTCP runs the traffic stage in a faking mode that is not
// the default: easy-faketcp. The other non-default modes of the pinned build
// (udp, icmp) are documented in docs/multi/tunnels/udp2raw.md with their own
// evidence; faketls/fakehttp do not exist in 20230206.0's --help.
func TestRawModeEasyFakeTCP(t *testing.T) { runNetnsStages(t, "easy-faketcp", false) }

// TestRawModeICMP runs the traffic stage in raw-mode icmp.
func TestRawModeICMP(t *testing.T) { runNetnsStages(t, "icmp", false) }

func runNetnsStages(t *testing.T, rawMode string, full bool) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux netns: " + runtime.GOOS + " cannot create network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to create network namespaces (ip netns add)")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("requires ip(8) from iproute2 to build the veth topology: " + err.Error())
	}
	requireBinary(t)

	suffix := randomHexBytes(4)
	nsA, nsB := "u2a"+suffix, "u2b"+suffix
	ifA, ifB := "v"+suffix+"a", "v"+suffix+"b" // <= 15 chars, the kernel's limit
	subnet := 1 + mustHex(t, suffix[0:2])%250
	ipA := fmt.Sprintf("10.250.%d.1", subnet)
	ipB := fmt.Sprintf("10.250.%d.2", subnet)

	// Baselines of everything this test must leave untouched (CONTRACT §2.3
	// rule 1): the host's own iptables ruleset and ip_forward.
	hostRulesBefore := hostCommand(t, "iptables-save")
	hostForwardBefore := hostCommand(t, "sysctl", "-n", "net.ipv4.ip_forward")

	teardown := spawnNetns(t, nsA, nsB, ifA, ifB, ipA, ipB)
	t.Cleanup(func() {
		teardown()
		out, _ := exec.Command("ip", "netns", "list").CombinedOutput()
		left := strings.TrimSpace(string(out))
		if strings.Contains(left, nsA) || strings.Contains(left, nsB) {
			t.Errorf("network namespaces left behind after the run: %s", left)
		}
		if after := hostCommand(t, "iptables-save"); after != hostRulesBefore {
			t.Errorf("the HOST iptables ruleset changed during the run\nbefore: %s\nafter:  %s",
				hostRulesBefore, after)
		}
		if after := hostCommand(t, "sysctl", "-n", "net.ipv4.ip_forward"); after != hostForwardBefore {
			t.Errorf("host net.ipv4.ip_forward changed: %s -> %s", hostForwardBefore, after)
		}
	})

	alloc := tunnel.NewAllocator()
	echo := alloc.AllocPair()
	plan := &netnsPlan{
		TempDir: t.TempDir(),
		IPA:     ipA,
		IPB:     ipB,
		PortsA:  alloc.AllocPair(),
		PortsB:  alloc.AllocPair(),
		PortsD:  alloc.AllocPair(),
		Echo:    echo.Listen,
		RawMode: rawMode,
		Full:    full,
		ID:      "u2r-" + randomHexBytes(6),
		DecoyID: "decoy-" + randomHexBytes(6),
	}
	planPath := filepath.Join(plan.TempDir, "plan.json")
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Logf("stages for raw_mode=%s (full=%v) in netns %s + %s over %s/%s", rawMode, full, nsA, nsB, ipA, ipB)

	// Side b first: it is the destination the datagrams have to reach.
	// The shared key rides in the environment (CONTRACT §2.3 rule 3): env or
	// a 0600 file, never a log line, never a committed file.
	key := randomHexBytes(16)
	b := spawnChild(t, nsB, "b", planPath, key)
	if err := waitFor(filepath.Join(plan.TempDir, "b.ready"), 45*time.Second); err != nil {
		dump(t, "side b", b)
		t.Fatalf("side b never came up: %v", err)
	}
	a := spawnChild(t, nsA, "a", planPath, key)
	if code := waitExit(t, a, 3*time.Minute); code != 0 {
		dump(t, "side a", a)
		t.Fatalf("stage run in %s exited %d", nsA, code)
	}
	dump(t, "side a", a)

	// Side b is told to stop, then checked for what it received.
	writeMarker(t, filepath.Join(plan.TempDir, "b.stop"))
	if code := waitExit(t, b, time.Minute); code != 0 {
		dump(t, "side b", b)
		t.Fatalf("side b exited %d", code)
	}
	dump(t, "side b", b)

	tx := readFile(t, filepath.Join(plan.TempDir, "a.tx"))
	rx := readFile(t, filepath.Join(plan.TempDir, "b.rx"))
	if tx == "" || rx == "" {
		t.Fatalf("missing destination-side digests: a.tx=%q b.rx=%q", tx, rx)
	}
	if tx != rx {
		t.Fatalf("the destination did not receive the bytes byte-for-byte: sent %s, received %s", tx, rx)
	}
	t.Logf("the destination received every payload byte-for-byte: sha256 %s", tx)
}

// netnsPlan is the one file both namespace children read: every port and
// address is chosen by the parent, so nothing is raced or guessed.
type netnsPlan struct {
	TempDir string       `json:"temp_dir"`
	IPA     string       `json:"ip_a"`
	IPB     string       `json:"ip_b"`
	PortsA  tunnel.Ports `json:"ports_a"`
	PortsB  tunnel.Ports `json:"ports_b"`
	PortsD  tunnel.Ports `json:"ports_d"`
	Echo    int          `json:"echo_port"`
	RawMode string       `json:"raw_mode"`
	Full    bool         `json:"full"`
	ID      string       `json:"tunnel_id"`
	DecoyID string       `json:"decoy_id"`
}

// spawnNetns builds the topology both children run in — two namespaces, one
// veth pair, one address each — and returns the teardown that removes it.
// The host's default route, its iptables ruleset and SSH are never touched;
// everything created here dies with the namespaces.
func spawnNetns(t *testing.T, nsA, nsB, ifA, ifB, ipA, ipB string) (cleanup func()) {
	t.Helper()
	run := func(optional bool, args ...string) {
		t.Helper()
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil && !optional {
			t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run(true, "ip", "netns", "del", nsA) // leftovers from a killed run
	run(true, "ip", "netns", "del", nsB)
	run(false, "ip", "netns", "add", nsA)
	run(false, "ip", "netns", "add", nsB)
	run(false, "ip", "link", "add", ifA, "type", "veth", "peer", "name", ifB)
	run(false, "ip", "link", "set", ifA, "netns", nsA)
	run(false, "ip", "link", "set", ifB, "netns", nsB)
	run(false, "ip", "netns", "exec", nsA, "ip", "addr", "add", ipA+"/24", "dev", ifA)
	run(false, "ip", "netns", "exec", nsB, "ip", "addr", "add", ipB+"/24", "dev", ifB)
	run(false, "ip", "netns", "exec", nsA, "ip", "link", "set", ifA, "up")
	run(false, "ip", "netns", "exec", nsB, "ip", "link", "set", ifB, "up")
	run(false, "ip", "netns", "exec", nsA, "ip", "link", "set", "lo", "up")
	run(false, "ip", "netns", "exec", nsB, "ip", "link", "set", "lo", "up")
	if out, err := exec.Command("ip", "netns", "exec", nsA, "ping", "-c", "1", "-W", "2", ipB).CombinedOutput(); err != nil {
		t.Fatalf("underlay across the veth pair: %v\n%s", err, out)
	}
	return func() {
		for _, ns := range []string{nsA, nsB} {
			// ip netns del fails while a process still holds the namespace;
			// the children are already gone by then, so this is a plain best
			// effort with the result checked by the caller's leftover scan.
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
	}
}

// childProc is one test binary running inside a namespace.
type childProc struct {
	cmd  *exec.Cmd
	out  *bytes.Buffer
	ns   string
	role string
}

func spawnChild(t *testing.T, ns, role, planPath, key string) *childProc {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0])
	cmd.Env = append(os.Environ(),
		childEnv+"="+role,
		planEnv+"="+planPath,
		SecretKey+"="+key,
	)
	setPgid(cmd)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child %s in %s: %v", role, ns, err)
	}
	return &childProc{cmd: cmd, out: buf, ns: ns, role: role}
}

// waitExit waits for a child, killing its whole process group (and with it any
// udp2raw it started) when the budget runs out.
func waitExit(t *testing.T, p *childProc, timeout time.Duration) int {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return 0
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		t.Fatalf("child %s: %v", p.role, err)
		return -1
	case <-time.After(timeout):
		killChild(p)
		t.Fatalf("child %s in %s did not finish within %s\n%s", p.role, p.ns, timeout, p.out.String())
		return -1
	}
}

func killChild(p *childProc) {
	if p.cmd.Process == nil {
		return
	}
	// The process group, so the udp2raw children go too.
	killGroup(p.cmd.Process.Pid)
	_, _ = p.cmd.Process.Wait()
}

func dump(t *testing.T, label string, p *childProc) {
	t.Helper()
	t.Logf("--- %s (%s) output ---\n%s", label, p.ns, p.out.String())
}

// waitFor blocks until path exists, so "side b is up" is a file the other
// namespace can see rather than a sleep that guesses.
func waitFor(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s never appeared", path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func writeMarker(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// hostCommand runs a read-only host command for the before/after baselines.
func hostCommand(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------------------
// bundle: the pinned fat bundle, extracted per platform

// requireBinary points TUNNEL_BUNDLE_DIR at the extracted pinned binary,
// unpacking the fat bundle when the directory only holds the archive. It
// asserts the archive's sha256 AND the platform of what it extracts — the
// tarball carries arm/mips/x86 builds too, and running the wrong one is a
// "works, but is the wrong build" failure.
func requireBinary(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("requires Linux: upstream ships no Windows binary in udp2raw_binaries.tar.gz (tag " +
			pinVersion + "), only linux/macos/arm/mips builds")
	}
	pin, ok := tunnel.PinFor(Tool)
	if !ok {
		t.Fatal("pins.json is not registered")
	}
	asset, err := pin.AssetFor(tunnel.PlatformKey())
	if err != nil {
		t.Skipf("no pinned asset for %s: %v", tunnel.PlatformKey(), err)
	}
	// The bundle is next to this worktree (tools/wt-u2r -> tools/tunnel-bundle)
	// in the main checkout, or wherever the operator pointed the gate.
	here, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(here, "..", "..", "..", "..")
	dirs := []string{
		os.Getenv("TUNNEL_BUNDLE_DIR"),
		filepath.Join(root, "..", "tunnel-bundle"),
		filepath.Join(root, "tools", "tunnel-bundle"),
		"/opt/tunnel-bundle",
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(d, filepath.FromSlash(asset.Bin))); err == nil {
			t.Setenv("TUNNEL_BUNDLE_DIR", d)
			if _, err := tunnel.ResolveBinary(Tool, d); err != nil {
				t.Fatalf("bundle %s holds %s but it does not satisfy the pin: %v", d, asset.Bin, err)
			}
			t.Logf("bundle %s -> %s (archive and binary sha256 verified against pins.json)", d, asset.Bin)
			return
		}
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		archive := filepath.Join(d, asset.Name)
		if _, err := os.Stat(archive); err != nil {
			continue
		}
		dir := extractFatBundle(t, archive, asset)
		t.Setenv("TUNNEL_BUNDLE_DIR", dir)
		if _, err := tunnel.ResolveBinary(Tool, dir); err != nil {
			t.Fatalf("extracted %s: %v", archive, err)
		}
		t.Logf("extracted %s -> %s (archive sha256 + platform asserted, binary verified against pins.json)",
			archive, filepath.Join(dir, asset.Bin))
		return
	}
	t.Skipf("no udp2raw binary on this host: set TUNNEL_BUNDLE_DIR to a directory holding %q or the pinned archive %s (looked in: %s)",
		asset.Bin, asset.Name, strings.Join(dirs, ", "))
}

// archiveMember is the fat bundle's member for each platform key. The
// tarball is one archive for every platform (pins.json lists it once), so the
// extract step — not the pin — is where "the right build" is decided.
var archiveMember = map[string]string{
	"linux-amd64": "udp2raw_amd64",
}

func extractFatBundle(t *testing.T, archive string, asset tunnel.PinAsset) string {
	t.Helper()
	sum, err := tunnel.FileSHA256(archive)
	if err != nil {
		t.Fatalf("hash %s: %v", archive, err)
	}
	if !strings.EqualFold(sum, asset.SHA256) {
		t.Fatalf("%s is %s, pin wants %s", archive, sum, asset.SHA256)
	}
	member, ok := archiveMember[tunnel.PlatformKey()]
	if !ok {
		t.Fatalf("no archive member recorded for platform %s", tunnel.PlatformKey())
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
	out := filepath.Join(dir, filepath.FromSlash(asset.Bin))
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read %s: %v", archive, err)
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != member {
			continue
		}
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
		assertPlatform(t, out, member)
		return dir
	}
	t.Fatalf("%s contains no %s", archive, member)
	return ""
}

// assertPlatform is the "extracting the wrong one yields a works-but-wrong
// build" guard: the member must be a 64-bit x86 ELF, whatever else the
// tarball carries.
func assertPlatform(t *testing.T, path, member string) {
	t.Helper()
	if tunnel.PlatformKey() != "linux-amd64" {
		return
	}
	head := make([]byte, 20)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := io.ReadFull(f, head); err != nil {
		t.Fatalf("%s: %v", member, err)
	}
	if !bytes.Equal(head[0:4], []byte{0x7f, 'E', 'L', 'F'}) {
		t.Fatalf("%s is not an ELF binary (magic %x)", member, head[0:4])
	}
	if head[4] != 2 { // ELFCLASS64
		t.Fatalf("%s is not a 64-bit build (class %d)", member, head[4])
	}
	if machine := binary.LittleEndian.Uint16(head[18:20]); machine != 0x3e { // EM_X86_64
		t.Fatalf("%s is not x86-64 (e_machine %#x) — the fat bundle also carries arm/mips builds", member, machine)
	}
}

// ---------------------------------------------------------------------------
// namespace children

func runChild(role string) int {
	plan, err := readPlan(os.Getenv(planEnv))
	if err != nil {
		fmt.Fprintf(os.Stderr, "child %s: plan: %v\n", role, err)
		return 2
	}
	switch role {
	case "a":
		return childA(plan)
	case "b":
		return childB(plan)
	}
	fmt.Fprintf(os.Stderr, "child: unknown role %q\n", role)
	return 2
}

func readPlan(path string) (*netnsPlan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p netnsPlan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func failStage(stage string, err error) int {
	fmt.Printf("stage %s: FAIL: %v\n", stage, err)
	return 1
}

func passStage(stage, detail string) {
	fmt.Printf("stage %s: PASS %s\n", stage, detail)
}

// childB is the destination namespace: a UDP echo service (the tunnel's
// target) plus side b of the tunnel, which must be up before side a starts.
func childB(p *netnsPlan) int {
	key := os.Getenv(SecretKey)
	if key == "" {
		fmt.Fprintln(os.Stderr, "child b: "+SecretKey+" is not set in the environment")
		return 2
	}

	echo, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Echo)))
	if err != nil {
		return failStage("echo-listen", err)
	}
	defer echo.Close()

	// The destination records every byte it received: the parent compares
	// this digest with what side a says it sent, so "arrived byte-for-byte"
	// is proved from the far end, not from the sender's own socket.
	got := sha256.New()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			got.Write(buf[:n])
			sum := sha256.Sum256(buf[:n])
			_, _ = echo.WriteTo(sum[:], addr)
		}
	}()
	passStage("destination-up", fmt.Sprintf("udp echo on 127.0.0.1:%d", p.Echo))

	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: filepath.Join(p.TempDir, "mgr-b")})
	defer m.Shutdown()
	spec := sideSpec(p, tunnel.SideB, p.ID, key, "")
	if err := m.Start(context.Background(), spec, p.PortsB); err != nil {
		return failStage("start-side-b", err)
	}
	passStage("side-b-up", fmt.Sprintf("udp2raw -s on %s:%d raw_mode=%s", p.IPB, p.PortsB.Listen, p.RawMode))

	writeMarkerReady(filepath.Join(p.TempDir, "b.ready"))

	deadline := time.Now().Add(4 * time.Minute)
	for {
		if _, err := os.Stat(filepath.Join(p.TempDir, "b.stop")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return failStage("side-b-wait", errors.New("parent never asked side b to stop"))
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Digest file: hex of everything the destination actually received.
	if err := os.WriteFile(filepath.Join(p.TempDir, "b.rx"), []byte(hex.EncodeToString(got.Sum(nil))), 0o600); err != nil {
		return failStage("destination-digest", err)
	}
	passStage("destination-digest", hex.EncodeToString(got.Sum(nil)))
	return 0
}

// childA is the source namespace and runs the stages.
func childA(p *netnsPlan) int {
	key := os.Getenv(SecretKey)
	if key == "" {
		fmt.Fprintln(os.Stderr, "child a: "+SecretKey+" is not set in the environment")
		return 2
	}
	if err := waitFor(filepath.Join(p.TempDir, "b.ready"), 45*time.Second); err != nil {
		return failStage("wait-side-b", err)
	}

	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: filepath.Join(p.TempDir, "mgr-a")})
	defer m.Shutdown()
	a := Adapter{}
	spec := sideSpec(p, tunnel.SideA, p.ID, key, "")
	ctx := context.Background()

	// ---- stage: traffic -------------------------------------------------
	if err := m.Start(ctx, spec, p.PortsA); err != nil {
		return failStage("traffic", fmt.Errorf("start side a: %w", err))
	}
	// One running digest over every payload that must reach the destination:
	// side b hashes exactly what it receives and the parent compares the two
	// after both children are gone.
	sent := sha256.New()
	stage, err := pushPayloads(p, 8, sent)
	if err != nil {
		return failStage("traffic", err)
	}
	passStage("traffic", fmt.Sprintf("8 UDP datagrams round-tripped through raw_mode=%s, destination digest %s", p.RawMode, stage))
	if err := writeTx(p, sent); err != nil {
		return failStage("traffic", err)
	}
	if !p.Full {
		// A non-default-mode run claims the traffic stage only. The other
		// three stages are the default-mode run's; saying so out loud here
		// is what keeps this from being a silent skip.
		for _, stage := range []string{"restart", "negative-control", "logs"} {
			fmt.Printf("stage %s: not-run (raw_mode=%s claim is the traffic stage; the four-stage run is raw_mode=faketcp)\n",
				stage, p.RawMode)
		}
		return 0
	}
	// ---- stage: restart -------------------------------------------------
	if err := m.Stop(p.ID); err != nil {
		return failStage("restart", fmt.Errorf("stop: %w", err))
	}
	first, err := a.Render(spec)
	if err != nil {
		return failStage("restart", fmt.Errorf("render: %w", err))
	}
	second, err := a.Render(spec)
	if err != nil {
		return failStage("restart", fmt.Errorf("second render: %w", err))
	}
	if first != second {
		return failStage("restart", fmt.Errorf("Render is not deterministic across a restart:\n%s\n---\n%s", first, second))
	}
	if err := m.Start(ctx, spec, p.PortsA); err != nil {
		return failStage("restart", fmt.Errorf("start again from the same Spec: %w", err))
	}
	again, err := pushPayloads(p, 8, sent)
	if err != nil {
		return failStage("restart", err)
	}
	passStage("restart", fmt.Sprintf("stopped, re-rendered byte-identical, started again, 8 more datagrams (digest %s)", again))

	// The destination-side digest is written before the negative control:
	// the payloads below must NOT arrive, so they are excluded from what the
	// parent compares.
	if err := writeTx(p, sent); err != nil {
		return failStage("traffic", err)
	}

	// ---- stage: negative-control ----------------------------------------
	if err := m.Stop(p.ID); err != nil {
		return failStage("negative-control", fmt.Errorf("stop: %w", err))
	}

	// (1) No key at all: Start must refuse by name, not run a tunnel udp2raw
	// would protect with its own public default string.
	os.Unsetenv(SecretKey)
	empty := spec.Clone()
	empty.Secrets = map[string]string{SecretKey: ""}
	err = m.Start(ctx, empty, p.PortsA)
	_ = os.Setenv(SecretKey, key)
	if !errors.Is(err, tunnel.ErrSecretUnresolved) {
		return failStage("negative-control", fmt.Errorf("an unresolved key must be refused with ErrSecretUnresolved, got: %v", err))
	}
	passStage("negative-control", "unresolved key refused: "+err.Error())

	// (2) A WRONG key: udp2raw cannot finish its handshake with a peer that
	// derives a different cipher, so the side never comes up and Start
	// refuses — the refusal itself, not a process that stayed alive, is the
	// assertion, and the error carries udp2raw's own handshake retry as
	// evidence. (The traffic-level half of this — a running tunnel with a
	// wrong key delivers nothing — is in
	// tools/runlogs/2a-udp2raw-probe-*.log, the raw probe.)
	wrong := spec.Clone()
	wrong.Secrets = map[string]string{SecretKey: "deliberately-wrong-key-" + randomHexBytes(6)}
	err = m.Start(ctx, wrong, p.PortsA)
	if err == nil {
		_ = m.Stop(p.ID)
		return failStage("negative-control", errors.New("a side with the wrong key came up as if healthy"))
	}
	if !strings.Contains(err.Error(), "did not come up") {
		return failStage("negative-control", fmt.Errorf("expected a handshake refusal, got: %v", err))
	}
	if !strings.Contains(err.Error(), "handshake") {
		return failStage("negative-control", fmt.Errorf("the refusal must carry udp2raw's own handshake evidence, got: %v", err))
	}
	passStage("negative-control", "wrong key refused: "+err.Error())
	if err := m.Stop(p.ID); err != nil && !errors.Is(err, tunnel.ErrNotRunning) {
		return failStage("logs", fmt.Errorf("stop: %w", err))
	}

	// ---- stage: logs ----------------------------------------------------
	if err := m.Start(ctx, spec, p.PortsA); err != nil {
		return failStage("logs", fmt.Errorf("start: %w", err))
	}
	mine := awaitRecords(m, p.ID)
	for _, rec := range mine {
		if rec.TunnelID != p.ID {
			return failStage("logs", fmt.Errorf("record in %s's ring carries tunnel_id %q", p.ID, rec.TunnelID))
		}
	}

	// The decoy is a side-b server on its own port: it binds, logs and never
	// handshakes, so its ring fills whatever the network does — all the
	// isolation check needs from it.
	decoy := sideSpec(p, tunnel.SideB, p.DecoyID, key, "")
	decoy.Params[tunnel.ParamListenPort] = strconv.Itoa(p.PortsD.Listen)
	if err := m.Start(ctx, decoy, p.PortsD); err != nil {
		return failStage("logs", fmt.Errorf("start decoy: %w", err))
	}
	theirs := awaitRecords(m, p.DecoyID)
	for _, rec := range theirs {
		if rec.TunnelID != p.DecoyID {
			return failStage("logs", fmt.Errorf("record in %s's ring carries tunnel_id %q", p.DecoyID, rec.TunnelID))
		}
	}
	for _, rec := range mine {
		if strings.Contains(rec.Detail, p.DecoyID) || strings.Contains(rec.Detail, strconv.Itoa(p.PortsD.Listen)) {
			return failStage("logs", fmt.Errorf("line from decoy tunnel %q appeared under %q: %q", p.DecoyID, p.ID, rec.Detail))
		}
	}
	for _, rec := range theirs {
		if strings.Contains(rec.Detail, p.ID) || strings.Contains(rec.Detail, strconv.Itoa(p.PortsA.Listen)) {
			return failStage("logs", fmt.Errorf("line from tunnel %q appeared under %q: %q", p.ID, p.DecoyID, rec.Detail))
		}
	}
	passStage("logs", fmt.Sprintf("%d records under %s, %d under decoy %s, no line crossed", len(mine), p.ID, len(theirs), p.DecoyID))
	return 0
}

func awaitRecords(m *tunnel.Manager, id string) []tunnel.Record {
	deadline := time.Now().Add(10 * time.Second)
	for {
		if recs := m.Logs(id); len(recs) > 0 {
			return recs
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// sideSpec builds one side's Spec from the plan. The panel sends ONE params
// map to both sides, so this is the same shape for a and b.
func sideSpec(p *netnsPlan, side tunnel.Side, id, key, overrideKey string) tunnel.Spec {
	params := map[string]string{
		tunnel.ParamListenPort: strconv.Itoa(listenOf(side, p)),
		ParamListenHost:        "0.0.0.0",
		ParamPeer:              net.JoinHostPort(p.IPB, strconv.Itoa(p.PortsB.Listen)),
		ParamTarget:            net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Echo)),
		ParamRawMode:           p.RawMode,
	}
	secret := key
	if overrideKey != "" {
		secret = overrideKey
	}
	return tunnel.Spec{
		TunnelID:    id,
		Tool:        Tool,
		ToolVersion: Version,
		Side:        side,
		Mode:        tunnel.ModeRelay,
		Params:      params,
		Secrets:     map[string]string{SecretKey: secret},
		Enabled:     true,
	}
}

func listenOf(side tunnel.Side, p *netnsPlan) int {
	if side == tunnel.SideB {
		return p.PortsB.Listen
	}
	return p.PortsA.Listen
}

// pushPayloads sends n random datagrams into side a's local UDP port and
// requires the destination's own answer back: the echo service replies with
// sha256(payload), so a single wrong byte anywhere in the path fails.
func pushPayloads(p *netnsPlan, n int, sink hash.Hash) (string, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(p.IPA, strconv.Itoa(p.PortsA.Listen)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	h := sha256.New()
	for i := 0; i < n; i++ {
		payload := make([]byte, 96)
		if _, err := rand.Read(payload); err != nil {
			return "", err
		}
		want := sha256.Sum256(payload)
		// Startup grace: a datagram sent in the instant after Start returns
		// can still be dropped by a side that is a heartbeat away from its
		// first exchange. Three seconds of silence fails; a wrong byte fails
		// immediately and is never retried.
		var reply []byte
		for attempt := 0; attempt < 3 && reply == nil; attempt++ {
			if _, err := conn.Write(payload); err != nil {
				return "", fmt.Errorf("datagram %d: %w", i, err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			buf := make([]byte, 64)
			got, err := conn.Read(buf)
			if err != nil {
				continue
			}
			reply = buf[:got]
		}
		if reply == nil {
			return "", fmt.Errorf("datagram %d: no reply through the tunnel after 3 attempts", i)
		}
		if !bytes.Equal(reply, want[:]) {
			return "", fmt.Errorf("datagram %d: destination saw different bytes (first difference at byte %d)",
				i, firstDiff(reply, want[:]))
		}
		h.Write(payload)
		sink.Write(payload)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeTx records what side a expects at the destination: one sha256 over
// every payload that must arrive, in order.
func writeTx(p *netnsPlan, sent hash.Hash) error {
	return os.WriteFile(filepath.Join(p.TempDir, "a.tx"), []byte(hex.EncodeToString(sent.Sum(nil))), 0o600)
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

// writeMarkerReady is child-side marker writing (no testing.T down here).
func writeMarkerReady(path string) {
	_ = os.WriteFile(path, []byte("1"), 0o600)
}
