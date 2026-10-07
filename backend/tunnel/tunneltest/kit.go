// Package tunneltest is the four-part test every Phase 3 tunnel adapter must
// pass, written so its author cannot skip a step: Run executes all four in
// order and fails the testing.T on the first one that does not hold.
//
//  1. traffic   — both sides up, payload pushed through loopback, asserted
//     byte-for-byte in both directions, and every side's Stats non-zero.
//  2. restart   — stop everything, re-Render from the same Spec (byte-identical
//     to the first render), start again with no manual step, traffic flows.
//  3. negative  — a deliberately wrong secret: the failure is an explicit
//     error, nothing arrives at the destination, never a half-open tunnel.
//  4. logs      — the log stream carries this tunnel_id, and no line from this
//     tunnel appears under another id.
//
// A step that cannot run must FAIL, not skip. There is no skip path in here.
//
// Usage (from node/backend/tunnel/<tool>/<tool>_test.go):
//
//	func TestRelay(t *testing.T) {
//	    t.Setenv(plain.SecretToken, "kit-secret") // whatever the factory declares
//	    tunneltest.Run(t, tunneltest.Kit{
//	        Adapter:  plain.Adapter{},
//	        NewSpec:  mySpecFactory, // func(tunneltest.Endpoints) tunnel.Spec
//	        Allocate: myAlloc,       // func() tunnel.Ports — one call per side
//	        Corrupt:  myCorrupt,     // func(*tunnel.Spec) — make Start fail
//	    })
//	}
package tunneltest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pasarguard/node/backend/tunnel"
)

// ioTimeout is the I/O budget for every loopback step: generous for a loaded
// CI box, short enough that a half-open tunnel fails instead of hanging.
const ioTimeout = 10 * time.Second

// payloadSize is the byte count pushed through the tunnel in each direction.
const payloadSize = 4096

// Endpoints is everything a spec factory needs to build one side's Spec. The
// kit has already allocated the ports and started the byte sink, so every
// field is final: the factory must bind e.Listen for side e.Side, have side a
// dial e.Peer, and have side b deliver to e.Target (mode=relay).
type Endpoints struct {
	TunnelID string
	Side     tunnel.Side
	Listen   string // host:port this side binds ("127.0.0.1:<port>")
	Peer     string // the other side's Listen
	Target   string // the kit's byte sink (what side b delivers to)
	Mode     string // tunnel.ModeRelay — pass it through to the Spec
}

// Kit is one adapter under test. Allocate and Corrupt are required: a kit
// missing them fails outright rather than skipping the steps they serve.
type Kit struct {
	Adapter tunnel.Adapter
	NewSpec func(e Endpoints) tunnel.Spec
	// Allocate returns the ports for one side. The kit calls it once per side
	// (a and b), and again for the decoy tunnel in step 4.
	Allocate func() tunnel.Ports
	// Corrupt mutates a spec so that starting it must fail (wrong token,
	// wrong key, unresolvable param). The kit applies it to side b only.
	Corrupt func(*tunnel.Spec)
}

// Run executes the four-part test and fails t on the first violation.
func Run(t *testing.T, k Kit) {
	t.Helper()
	if err := k.run(t.TempDir(), t.Cleanup); err != nil {
		t.Fatalf("tunneltest: %v", err)
	}
}

// run is the testable core: it never calls Fatal itself, so this package's own
// tests can assert that a broken adapter really does fail a step.
func (k Kit) run(tempDir string, cleanup func(func())) error {
	if k.Adapter == nil {
		return fmt.Errorf("kit is incomplete: Adapter is nil (a step cannot run)")
	}
	if k.NewSpec == nil {
		return fmt.Errorf("kit is incomplete: NewSpec is nil (a step cannot run)")
	}
	if k.Allocate == nil {
		return fmt.Errorf("kit is incomplete: the Allocate hook is required — a step must not be skipped")
	}
	if k.Corrupt == nil {
		return fmt.Errorf("kit is incomplete: the Corrupt hook is required — the negative control must not be skipped")
	}

	sk, err := newSink()
	if err != nil {
		return fmt.Errorf("step setup: byte sink: %w", err)
	}
	defer sk.close()

	m := tunnel.NewManager(tunnel.ManagerOptions{Dir: tempDir})
	cleanup(m.Shutdown)

	portsA, portsB := k.Allocate(), k.Allocate()
	id := "kit-" + randomHex(8)
	epsA, epsB := endpoints(id, portsA, portsB, sk.addr())
	specA, specB := k.NewSpec(epsA), k.NewSpec(epsB)

	steps := []struct {
		name string
		fn   func() error
	}{
		{"render-determinism", func() error {
			return assertDeterministic(k.Adapter, specA, specB)
		}},
		{"traffic", func() error {
			if err := m.Start(context.Background(), specA, portsA); err != nil {
				return fmt.Errorf("start side a: %w", err)
			}
			if err := m.Start(context.Background(), specB, portsB); err != nil {
				return fmt.Errorf("start side b: %w", err)
			}
			return roundTrip(m, sk, epsA.Listen)
		}},
		{"restart", func() error {
			if err := m.Stop(id); err != nil {
				return fmt.Errorf("stop before restart: %w", err)
			}
			// Re-render the same Spec after the stop: byte-identical output is
			// what makes "came back from config alone" mean anything.
			if err := assertDeterministic(k.Adapter, specA, specB); err != nil {
				return err
			}
			if err := m.Start(context.Background(), specA, portsA); err != nil {
				return fmt.Errorf("restart side a: %w", err)
			}
			if err := m.Start(context.Background(), specB, portsB); err != nil {
				return fmt.Errorf("restart side b: %w", err)
			}
			return roundTrip(m, sk, epsA.Listen)
		}},
		{"negative-control", func() error {
			return negativeControl(m, k, specA, specB, portsA, portsB, epsA, sk)
		}},
		{"logs", func() error {
			return logIsolation(m, k, specA, specB, portsA, portsB, epsA, sk)
		}},
	}

	for _, s := range steps {
		if err := s.fn(); err != nil {
			return fmt.Errorf("step %s: %w", s.name, err)
		}
	}
	return nil
}

// assertDeterministic renders every spec twice and requires byte-identical
// output. This is what makes the restart step meaningful: a render that drifts
// would restart into a different tunnel.
func assertDeterministic(a tunnel.Adapter, specs ...tunnel.Spec) error {
	for _, spec := range specs {
		first, err := a.Render(spec)
		if err != nil {
			return fmt.Errorf("render %s/%s: %w", spec.TunnelID, spec.Side, err)
		}
		second, err := a.Render(spec)
		if err != nil {
			return fmt.Errorf("second render %s/%s: %w", spec.TunnelID, spec.Side, err)
		}
		if first != second {
			return fmt.Errorf("Render is not deterministic for tunnel %s side %s:\nfirst:\n%s\nsecond:\n%s",
				spec.TunnelID, spec.Side, first, second)
		}
	}
	return nil
}

// roundTrip pushes payloadSize random bytes through the tunnel and requires
// the exact answer back — not "connected", not "some bytes": both directions
// byte-for-byte, plus non-zero aggregate Stats on every running side.
func roundTrip(m *tunnel.Manager, sk *sinkT, listen string) error {
	payload := randomBytes(payloadSize)
	want := randomBytes(payloadSize)
	sk.reset(want)

	conn, err := net.DialTimeout("tcp", listen, ioTimeout)
	if err != nil {
		return fmt.Errorf("dial %s: %w", listen, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))

	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	got := make([]byte, payloadSize)
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if string(got) != string(want) {
		return fmt.Errorf("down direction differs: %d bytes back, first difference at byte %d",
			len(got), firstDiff(got, want))
	}

	atSink := sk.received()
	if string(atSink) != string(payload) {
		return fmt.Errorf("up direction differs at the destination: %d bytes arrived, first difference at byte %d",
			len(atSink), firstDiff(atSink, payload))
	}

	// Stats are sampled, not transactional: the write that carried the
	// response may still be a few instructions away from incrementing its
	// counter when the client's read returns. Poll instead of sleeping blind.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if bad := unsettledStats(m); bad == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s", unsettledStats(m))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// unsettledStats returns "" when every running side counts both directions,
// or a message naming the side that does not.
func unsettledStats(m *tunnel.Manager) string {
	for _, st := range m.List() {
		if st.BytesUp == 0 || st.BytesDown == 0 {
			return fmt.Sprintf("Stats for tunnel %s side %s: up=%d down=%d — both directions must be counted",
				st.TunnelID, st.Side, st.BytesUp, st.BytesDown)
		}
	}
	return ""
}

// negativeControl starts side a with a good spec and side b with a corrupted
// one. Whatever the adapter does, three things must hold: the corruption is an
// explicit error somewhere (a failed Start, or an Error-level log record), the
// destination never receives a byte, and the client does not get a tunnel that
// silently swallows its data.
func negativeControl(m *tunnel.Manager, k Kit, specA, specB tunnel.Spec, portsA, portsB tunnel.Ports, epsA Endpoints, sk *sinkT) error {
	if err := m.Stop(specA.TunnelID); err != nil && !errors.Is(err, tunnel.ErrNotRunning) {
		return err
	}
	if err := m.Start(context.Background(), specA, portsA); err != nil {
		return fmt.Errorf("start side a (good): %w", err)
	}

	bad := specB.Clone()
	k.Corrupt(&bad)
	before := len(sk.received())
	startErr := m.Start(context.Background(), bad, portsB)
	mark := time.Now().Add(-time.Minute).UnixMilli()

	conn, err := net.DialTimeout("tcp", epsA.Listen, ioTimeout)
	if err != nil {
		// Refusing the connection outright is also an explicit failure.
		if startErr != nil {
			return nil
		}
		return fmt.Errorf("dial %s with a corrupted side b: %w", epsA.Listen, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))
	_, _ = conn.Write(randomBytes(payloadSize))
	buf := make([]byte, payloadSize)
	_, readErr := io.ReadFull(conn, buf)

	if arrived := len(sk.received()) - before; arrived != 0 {
		return fmt.Errorf("corrupted secret: %d byte(s) reached the destination anyway", arrived)
	}
	if readErr == nil {
		return fmt.Errorf("corrupted secret: tunnel stayed open and answered instead of failing")
	}

	// The refusal must be explicit somewhere: a Start that rejected the spec,
	// or an Error-level record from the attempt. Checked after the dial — a
	// handshake-level rejection only happens once a client shows up — and
	// polled, because the manager's pump delivers records asynchronously.
	if startErr == nil {
		deadline := time.Now().Add(ioTimeout)
		for !hasRecentError(m.Logs(specA.TunnelID), mark) {
			if time.Now().After(deadline) {
				return fmt.Errorf("corrupted secret produced no explicit error: Start succeeded and no Error-level log record was emitted")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	// Leave no half-started state for step 4.
	if err := m.Stop(specA.TunnelID); err != nil && !errors.Is(err, tunnel.ErrNotRunning) {
		return err
	}
	return nil
}

// logIsolation starts the tunnel again plus a decoy tunnel, then proves the
// log stream is addressable by tunnel_id and that no line from one tunnel
// lands under the other's id.
func logIsolation(m *tunnel.Manager, k Kit, specA, specB tunnel.Spec, portsA, portsB tunnel.Ports, epsA Endpoints, sk *sinkT) error {
	if err := m.Stop(specA.TunnelID); err != nil && !errors.Is(err, tunnel.ErrNotRunning) {
		return err
	}

	stream, cancel := m.Subscribe(256)
	defer cancel()

	if err := m.Start(context.Background(), specA, portsA); err != nil {
		return fmt.Errorf("start side a: %w", err)
	}
	if err := m.Start(context.Background(), specB, portsB); err != nil {
		return fmt.Errorf("start side b: %w", err)
	}

	decoyA, decoyB := k.Allocate(), k.Allocate()
	// Fresh id, not a suffix of the first: a decoy named "kit-X-decoy" would
	// contain "kit-X" as a substring and the content check would flag the
	// decoy's own lines.
	decoyID := "decoy-" + randomHex(8)
	dA, dB := endpoints(decoyID, decoyA, decoyB, sk.addr())
	if err := m.Start(context.Background(), k.NewSpec(dA), decoyA); err != nil {
		return fmt.Errorf("start decoy side a: %w", err)
	}
	if err := m.Start(context.Background(), k.NewSpec(dB), decoyB); err != nil {
		return fmt.Errorf("start decoy side b: %w", err)
	}

	// The live stream must carry this tunnel_id.
	if err := awaitStreamRecord(stream, specA.TunnelID, decoyID); err != nil {
		return err
	}

	mine := m.Logs(specA.TunnelID)
	if len(mine) == 0 {
		return fmt.Errorf("tunnel %s produced no log records", specA.TunnelID)
	}
	theirs := m.Logs(decoyID)
	if len(theirs) == 0 {
		return fmt.Errorf("decoy tunnel %s produced no log records — the isolation check would prove nothing", decoyID)
	}

	for _, rec := range mine {
		if rec.TunnelID != specA.TunnelID {
			return fmt.Errorf("record in %s's ring carries tunnel_id %q", specA.TunnelID, rec.TunnelID)
		}
		if mentionsAny(rec.Detail, decoyID, dA.Listen, dB.Listen) {
			return fmt.Errorf("line from decoy tunnel %q appeared under %q: %q", decoyID, specA.TunnelID, rec.Detail)
		}
	}
	for _, rec := range theirs {
		if rec.TunnelID != decoyID {
			return fmt.Errorf("record in %s's ring carries tunnel_id %q", decoyID, rec.TunnelID)
		}
		if mentionsAny(rec.Detail, specA.TunnelID, epsA.Listen) {
			return fmt.Errorf("line from tunnel %q appeared under %q: %q", specA.TunnelID, decoyID, rec.Detail)
		}
	}

	for _, id := range []string{specA.TunnelID, decoyID} {
		if err := m.Stop(id); err != nil && !errors.Is(err, tunnel.ErrNotRunning) {
			return err
		}
	}
	return nil
}

func hasRecentError(recs []tunnel.Record, sinceMs int64) bool {
	for _, rec := range recs {
		if rec.Level == "Error" && rec.TsUnixMs >= sinceMs {
			return true
		}
	}
	return false
}

func mentionsAny(detail string, needles ...string) bool {
	for _, n := range needles {
		if n != "" && strings.Contains(detail, n) {
			return true
		}
	}
	return false
}

// awaitStreamRecord waits for one record whose tunnel_id is want, rejecting a
// record that carries neither the tunnel under test nor its decoy.
func awaitStreamRecord(stream <-chan tunnel.Record, want, decoy string) error {
	deadline := time.After(ioTimeout)
	for {
		select {
		case rec, ok := <-stream:
			if !ok {
				return fmt.Errorf("log stream closed before any record for %s arrived", want)
			}
			if rec.TunnelID != want && rec.TunnelID != decoy {
				return fmt.Errorf("stream record carries tunnel_id %q, want %q or %q", rec.TunnelID, want, decoy)
			}
			if rec.TunnelID == want {
				return nil
			}
		case <-deadline:
			return fmt.Errorf("no log record with tunnel_id %q reached the stream", want)
		}
	}
}

func endpoints(id string, a, b tunnel.Ports, target string) (Endpoints, Endpoints) {
	one := func(p tunnel.Ports) string { return fmt.Sprintf("127.0.0.1:%d", p.Listen) }
	return Endpoints{
		TunnelID: id, Side: tunnel.SideA, Listen: one(a), Peer: one(b), Target: target, Mode: tunnel.ModeRelay,
	}, Endpoints{
		TunnelID: id, Side: tunnel.SideB, Listen: one(b), Peer: one(a), Target: target, Mode: tunnel.ModeRelay,
	}
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

func randomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("tunneltest: crypto/rand failed: " + err.Error())
	}
	return buf
}

func randomHex(n int) string {
	b := randomBytes(n)
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// byte sink: the destination side b delivers to, and the source of the bytes
// the client reads back. One per kit run.
type sinkT struct {
	ln   net.Listener
	mu   sync.Mutex
	want []byte // written to every peer after it delivers payloadSize bytes
	got  []byte // everything received since the last reset
}

func newSink() (*sinkT, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &sinkT{ln: ln, want: randomBytes(payloadSize)}
	go s.serve()
	return s, nil
}

func (s *sinkT) addr() string { return s.ln.Addr().String() }

func (s *sinkT) close() { _ = s.ln.Close() }

// reset arms the reply and clears the receive buffer for one round trip.
func (s *sinkT) reset(want []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.want = want
	s.got = nil
}

func (s *sinkT) received() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]byte, len(s.got))
	copy(out, s.got)
	return out
}

func (s *sinkT) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(ioTimeout))
			buf := make([]byte, payloadSize)
			if _, err := io.ReadFull(c, buf); err != nil {
				return
			}
			s.mu.Lock()
			s.got = append(s.got, buf...)
			want := s.want
			s.mu.Unlock()
			_, _ = c.Write(want)
		}(conn)
	}
}
