package sysstats

import (
	"context"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/net"
)

func TestGetSystemStatsCancelledContextReturnsImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := GetSystemStats(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected cancelled context to return an error")
	}
	if elapsed >= sampleInterval {
		t.Fatalf("GetSystemStats blocked for %s, want return before %s sample wait", elapsed, sampleInterval)
	}
}

func TestWaitSampleStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)

	start := time.Now()
	err := waitSample(ctx, sampleInterval)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected waitSample to return a context error")
	}
	if elapsed >= sampleInterval {
		t.Fatalf("waitSample blocked for %s, want cancel before %s", elapsed, sampleInterval)
	}
}

func TestBandwidthDeltaExcludesLoopback(t *testing.T) {
	first := []net.IOCountersStat{
		{Name: "lo", BytesRecv: 100, BytesSent: 200},
		{Name: "eth0", BytesRecv: 1000, BytesSent: 2000},
	}
	second := []net.IOCountersStat{
		{Name: "lo", BytesRecv: 5000, BytesSent: 6000},
		{Name: "eth0", BytesRecv: 1100, BytesSent: 2300},
	}

	rx, tx := bandwidthDelta(first, second)
	if rx != 100 {
		t.Fatalf("incoming bytes: got %d, want 100 (lo excluded)", rx)
	}
	if tx != 300 {
		t.Fatalf("outgoing bytes: got %d, want 300 (lo excluded)", tx)
	}
}
