package controller

import (
	"fmt"
	"testing"
	"time"

	nodeLogger "github.com/pasarguard/node/logger"
)

// TestLogSourcesCarryEachCoresOwnChannel: every running core appears once, in
// id order, and each carries the channel only it publishes to. This is the list
// the GetLogs fan-out iterates, so a wrong entry here becomes a wrong core_id on
// the wire (CONTRACT §3.1).
func TestLogSourcesCarryEachCoresOwnChannel(t *testing.T) {
	c := testController(t)

	for i, id := range []uint64{1, 2, 3} {
		if err := startFake(t, c, id, logLabel(i), 0); err != nil {
			t.Fatalf("start core %d: %v", id, err)
		}
	}

	refs := c.LogSources()
	if len(refs) != 3 {
		t.Fatalf("log sources = %d, want 3", len(refs))
	}

	seen := map[string]uint64{}
	for i, ref := range refs {
		wantID := uint64(i + 1)
		if ref.ID != wantID {
			t.Errorf("log source %d has id %d, want %d (id order matters)", i, ref.ID, wantID)
		}
		liner, ok := ref.Backend.(nodeLogger.LogLiner)
		if !ok {
			t.Fatalf("core %d does not expose a classified channel", ref.ID)
		}
		ch := liner.LogLines()
		if ch == nil {
			t.Fatalf("core %d has a nil classified channel", ref.ID)
		}
		key := fmt.Sprintf("%p", ch)
		if prev, dup := seen[key]; dup {
			t.Fatalf("cores %d and %d share one channel", prev, ref.ID)
		}
		seen[key] = ref.ID
	}
}

// TestClassifiedChannelsNeverMix is the negative assertion at the source: a
// line published on core 2's channel is never visible on core 1's, so the
// handler cannot attribute it to core 1.
func TestClassifiedChannelsNeverMix(t *testing.T) {
	c := testController(t)

	if err := startFake(t, c, 1, "mix1", 0); err != nil {
		t.Fatalf("start core 1: %v", err)
	}
	if err := startFake(t, c, 2, "mix2", 0); err != nil {
		t.Fatalf("start core 2: %v", err)
	}

	coreOne, coreTwo := fakeLookup(t, "mix1"), fakeLookup(t, "mix2")
	one, two := coreOne.LogLines(), coreTwo.LogLines()

	const n = 10
	for i := range n {
		coreOne.publish(nodeLogger.LogLine{Detail: "core-one-line", Level: nodeLogger.LogInfo, TsUnixMs: int64(i + 1)})
		coreTwo.publish(nodeLogger.LogLine{Detail: "core-two-line", Level: nodeLogger.LogError, TsUnixMs: int64(i + 1)})
	}

	for range n {
		got := <-one
		if got.Detail != "core-one-line" {
			t.Fatalf("core 1's channel delivered another core's line: %q", got.Detail)
		}
		if got.Level != nodeLogger.LogInfo {
			t.Errorf("core 1 line has level %q, want Info", got.Level)
		}
		if got.TsUnixMs == 0 {
			t.Error("a record has a zero ts_unix_ms")
		}
	}
	for range n {
		got := <-two
		if got.Detail != "core-two-line" {
			t.Fatalf("core 2's channel delivered another core's line: %q", got.Detail)
		}
		if got.Level != nodeLogger.LogError {
			t.Errorf("core 2 line has level %q, want Error", got.Level)
		}
	}

	// Both channels are drained to the brim and nothing extra crossed.
	select {
	case extra := <-one:
		t.Fatalf("core 1's channel has a surplus record: %q", extra.Detail)
	default:
	}
	select {
	case extra := <-two:
		t.Fatalf("core 2's channel has a surplus record: %q", extra.Detail)
	default:
	}
}

// TestTimestampsAreMonotonicAcrossACore: a core's own stream never goes
// backwards in time (CONTRACT §3.1).
func TestTimestampsAreMonotonicAcrossACore(t *testing.T) {
	c := testController(t)
	if err := startFake(t, c, 1, "ts1", 0); err != nil {
		t.Fatalf("start core 1: %v", err)
	}
	core := fakeLookup(t, "ts1")
	ch := core.LogLines()

	var last int64
	for i := range 8 {
		last = int64(1700000000000 + i*10)
		core.publish(nodeLogger.LogLine{Detail: "seq", Level: nodeLogger.LogInfo, TsUnixMs: last})
	}

	var prev int64
	for range 8 {
		got := <-ch
		if got.TsUnixMs <= prev {
			t.Fatalf("ts_unix_ms went backwards: %d after %d", got.TsUnixMs, prev)
		}
		prev = got.TsUnixMs
	}
	if prev != last {
		t.Errorf("final ts_unix_ms = %d, want %d", prev, last)
	}
}

// TestStoppedCoreDropsOutOfTheLogStream: a stopped core must not keep feeding
// the multiplexed stream.
func TestStoppedCoreDropsOutOfTheLogStream(t *testing.T) {
	c := testController(t)
	if err := startFake(t, c, 1, "stop1", 0); err != nil {
		t.Fatalf("start core 1: %v", err)
	}
	if err := startFake(t, c, 2, "stop2", 0); err != nil {
		t.Fatalf("start core 2: %v", err)
	}

	c.DisconnectCore(2)

	refs := c.LogSources()
	if len(refs) != 1 || refs[0].ID != 1 {
		t.Fatalf("log sources after stopping core 2 = %v, want just core 1", refs)
	}
}

// TestSlowConsumerDoesNotWedgeACore: a core nobody is reading from keeps
// running. The non-blocking send is the reason, and it is load-bearing.
func TestSlowConsumerDoesNotWedgeACore(t *testing.T) {
	c := testController(t)
	if err := startFake(t, c, 1, "slow1", 0); err != nil {
		t.Fatalf("start core 1: %v", err)
	}
	core := fakeLookup(t, "slow1")

	produced := make(chan struct{})
	go func() {
		defer close(produced)
		for range 50_000 {
			core.publish(nodeLogger.LogLine{Detail: "flood", Level: nodeLogger.LogInfo, TsUnixMs: 1})
		}
	}()

	select {
	case <-produced:
	case <-time.After(15 * time.Second):
		t.Fatal("a full core log channel wedged the core")
	}
}

// TestCoreIDZeroIsTheDefaultCoreInLogs: core_id 0 on the wire is the node's
// default core — core 1 — the same mapping normalizeCoreID gives every other
// request path.
func TestCoreIDZeroIsTheDefaultCoreInLogs(t *testing.T) {
	c := testController(t)
	for i, id := range []uint64{1, 2} {
		if err := startFake(t, c, id, logLabel(i), 0); err != nil {
			t.Fatalf("start core %d: %v", id, err)
		}
	}

	refs := c.LogSources()
	if len(refs) == 0 {
		t.Fatal("no log sources")
	}
	if got := normalizeCoreID(0); got != refs[0].ID {
		t.Errorf("core_id 0 resolves to %d, want the first running core (%d)", got, refs[0].ID)
	}
}

func logLabel(i int) string {
	return "logs" + string(rune('0'+i))
}
