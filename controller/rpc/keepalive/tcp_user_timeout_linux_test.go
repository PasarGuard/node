//go:build linux

package keepalive_test

import (
	"context"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

func sockaddrIs(sa unix.Sockaddr, want *net.TCPAddr) bool {
	in4, ok := sa.(*unix.SockaddrInet4)
	if !ok {
		return false
	}
	return in4.Port == want.Port && net.IP(in4.Addr[:]).Equal(want.IP)
}

func acceptedSocketUserTimeout(t *testing.T, node, client *net.TCPAddr) time.Duration {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		local, err := unix.Getsockname(fd)
		if err != nil || !sockaddrIs(local, node) {
			continue
		}
		peer, err := unix.Getpeername(fd)
		if err != nil || !sockaddrIs(peer, client) {
			continue
		}
		ms, err := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
		if err != nil {
			t.Fatalf("getsockopt TCP_USER_TIMEOUT: %v", err)
		}
		return time.Duration(ms) * time.Millisecond
	}
	t.Fatalf("no socket in this process was accepted on %v from %v", node, client)
	return 0
}

func TestNodeKeepsGrpcDefaultTCPUserTimeoutOnPanelConnections(t *testing.T) {
	t.Parallel()
	addr, certPath, key := startNode(t)
	var clientAddr atomic.Pointer[net.TCPAddr]
	conn := dialNode(t, addr, certPath, grpc.WithContextDialer(func(ctx context.Context, target string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
		if err == nil {
			clientAddr.Store(c.LocalAddr().(*net.TCPAddr))
		}
		return c, err
	}))
	baseInfo(t, conn, key)

	nodeAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	got := acceptedSocketUserTimeout(t, nodeAddr, clientAddr.Load())
	t.Logf("TCP_USER_TIMEOUT on the accepted panel connection: %s", got)
	if got != 20*time.Second {
		t.Fatalf("TCP_USER_TIMEOUT on the accepted panel connection is %s; grpc-go's default keepalive Timeout gives 20s, and a lower value aborts a stalling slow link sooner", got)
	}
}
