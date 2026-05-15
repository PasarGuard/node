//go:build linux

package wireguard

import (
	"net"
	"net/http"
	"syscall"

	"golang.org/x/sys/unix"
)

func latencyHTTPTransport(iface string) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if iface == "" {
		return transport
	}

	dialer := &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var controlErr error
			if err := c.Control(func(fd uintptr) {
				controlErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			}); err != nil {
				return err
			}
			return controlErr
		},
	}
	transport.DialContext = dialer.DialContext
	return transport
}
