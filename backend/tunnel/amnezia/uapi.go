package amnezia

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"time"
)

// socketDirectory is amneziawg-go's uapi socket directory —
// ipc/uapi_unix.go's `socketDirectory = "/var/run/amneziawg"`. It is a
// pathname socket, so the node process reaches it even when the daemon lives
// in another network namespace (abstract sockets are namespaced; pathname
// ones are not). Proven on the reference host:
// tools/runlogs/2a-amnezia-uapi-crossnetns-20261008T145936Z.log
const socketDirectory = "/var/run/amneziawg"

// sockPath joins with forward slashes on purpose: Render prints this path, and
// a config rendered on Windows must be byte-identical to one rendered on the
// Linux node it runs on. Dialing a unix socket on Linux takes it as-is.
func sockPath(ifname string) string {
	return path.Join(socketDirectory, ifname+".sock")
}

// uapiConn is one connection to one side's amneziawg-go control socket.
// The protocol is wireguard-go's xplatform text protocol with this fork's
// framing:
//
//	set=1\n<key>=<value>\n…\n\n   a BLANK line ends a set (not "end")
//	get=1\n\n
//
// every operation is answered with "errno=<n>\n\n". There is no message=
// field, so the errno is all the wire carries — the daemon's own explanation
// reaches this tunnel's log ring through the stderr pump.
type uapiConn struct {
	c net.Conn
	r *bufio.Reader
}

func dialUAPI(ifname string, timeout time.Duration) (*uapiConn, error) {
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.Dial("unix", sockPath(ifname))
		if err == nil {
			return &uapiConn{c: c, r: bufio.NewReader(c)}, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("uapi socket %s: %w", sockPath(ifname), err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (u *uapiConn) Close() error { return u.c.Close() }

// do sends one operation and returns its payload lines in order (peer blocks
// repeat their keys, so order matters and a map cannot hold them).
func (u *uapiConn) do(req string) ([]string, error) {
	_ = u.c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(u.c, req); err != nil {
		return nil, fmt.Errorf("uapi write: %w", err)
	}
	var out []string
	for {
		line, err := u.r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("uapi read: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "errno=") {
			code, _ := strconv.Atoi(strings.TrimPrefix(line, "errno="))
			if code != 0 {
				return out, uapiErrno(code)
			}
			return out, nil
		}
		out = append(out, line)
	}
}

// set applies one configuration block; payload must already end with the
// blank line that terminates a set.
func (u *uapiConn) set(payload string) error {
	_, err := u.do("set=1\n" + payload)
	return err
}

// get returns the device's state. The reply carries private_key=<hex> — the
// caller must never log it raw.
func (u *uapiConn) get() ([]string, error) {
	return u.do("get=1\n\n")
}

// uapiErrno turns the daemon's bare errno into a sentence. This is the set the
// uapi parser actually produces.
func uapiErrno(code int) error {
	switch code {
	case -22:
		return fmt.Errorf("uapi set refused: errno=-22 (invalid argument — the daemon rejected a value)")
	case -71:
		return fmt.Errorf("uapi set refused: errno=-71 (protocol error — the daemon could not parse the request)")
	case -19:
		return fmt.Errorf("uapi set refused: errno=-19 (no such device)")
	case -16:
		return fmt.Errorf("uapi set refused: errno=-16 (device or resource busy)")
	case -17:
		return fmt.Errorf("uapi set refused: errno=-17 (file exists)")
	default:
		return fmt.Errorf("uapi refused: errno=%d", code)
	}
}

// peerStats is one peer's counters as the daemon reports them.
type peerStats struct {
	LastHandshake int64
	Tx, Rx        uint64
}

// parseGet walks a get reply in order and returns the device listen port plus
// one entry per peer block (each starts at "public_key=").
func parseGet(lines []string) (uint32, []peerStats) {
	var (
		port  uint32
		peers []peerStats
		cur   *peerStats
	)
	flush := func() {
		if cur != nil {
			peers = append(peers, *cur)
			cur = nil
		}
	}
	for _, line := range lines {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "listen_port":
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				port = uint32(n)
			}
		case "public_key":
			flush()
			cur = &peerStats{}
		case "tx_bytes", "rx_bytes", "last_handshake_time_sec":
			if cur == nil {
				continue
			}
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				continue
			}
			switch k {
			case "tx_bytes":
				cur.Tx = n
			case "rx_bytes":
				cur.Rx = n
			case "last_handshake_time_sec":
				cur.LastHandshake = int64(n)
			}
		}
	}
	flush()
	return port, peers
}

// hexKey turns a base64 Curve25519 key into the hex form the uapi speaks.
func hexKey(b64, what string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("%s is not a base64 Curve25519 key (32 bytes after decoding)", what)
	}
	return hex.EncodeToString(raw), nil
}
