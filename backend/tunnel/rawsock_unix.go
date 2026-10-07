//go:build !windows

package tunnel

import "golang.org/x/sys/unix"

// probeRawSocket opens and immediately closes an AF_INET/SOCK_RAW socket. The
// failure mode that matters is EPERM, which is exactly what a packet-level
// tunnel hits on a host without root or CAP_NET_RAW.
func probeRawSocket() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}
