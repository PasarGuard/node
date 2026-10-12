package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// mgmtTimeout bounds one management round trip. The socket is local, so a slow
// answer means the child is gone or wedged, not busy.
const mgmtTimeout = 10 * time.Second

// mgmtPasswordFile is where the node writes the management password for
// openvpn's own `management <path> unix <pw-file>` directive. It is never
// printed, never put in the config and never returned over RPC.
const mgmtPasswordFile = "mgmt.pw"

// mgmtSocketFile is the unix socket openvpn creates in the core directory.
const mgmtSocketFile = "mgmt.sock"

// Management is a live handle on one core's OpenVPN management interface.
//
// This is the seam accounting-quota uses for `kill` and for the session list
// (LEGACY-VPN.md 4b/4d): one open connection, one mutex, because the interface
// accepts a single client at a time and a half-read reply would be attributed
// to the wrong command.
type Management struct {
	socket   string
	password string

	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
}

func newManagement(socket, password string) *Management {
	return &Management{socket: socket, password: password}
}

// Close drops the connection. The next command redials.
func (m *Management) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeLocked()
}

func (m *Management) closeLocked() {
	if m.conn != nil {
		_ = m.conn.Close()
		m.conn = nil
		m.reader = nil
	}
}

// dialLocked connects and performs the password handshake.
//
// The prompt is the trap: with a pw-file configured, openvpn writes
// `ENTER PASSWORD:` and NOTHING else — no newline (measured, LEGACY-VPN.md 3
// D0). A line-based reader blocks until the timeout and the interface looks
// dead, so this reads byte by byte until the real `>` prompt arrives.
func (m *Management) dialLocked(ctx context.Context) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", m.socket)
	if err != nil {
		return fmt.Errorf("openvpn: management socket %s: %w", m.socket, err)
	}
	m.conn = conn
	m.reader = bufio.NewReader(conn)

	var buf []byte
	sent := false
	one := make([]byte, 1)
	for {
		if err := conn.SetReadDeadline(deadlineFrom(ctx, mgmtTimeout)); err != nil {
			m.closeLocked()
			return err
		}
		if _, err := m.reader.Read(one); err != nil {
			m.closeLocked()
			return fmt.Errorf("openvpn: management handshake: %w", err)
		}
		buf = append(buf, one[0])
		if !sent && bytes.Contains(buf, []byte("ENTER PASSWORD:")) {
			if _, err := conn.Write([]byte(m.password + "\n")); err != nil {
				m.closeLocked()
				return fmt.Errorf("openvpn: management password: %w", err)
			}
			sent = true
			buf = buf[:0]
		}
		if bytes.HasSuffix(buf, []byte("\n>")) || bytes.Equal(buf, []byte(">")) {
			return nil
		}
		if bytes.Contains(buf, []byte("ERROR:")) || bytes.Contains(buf, []byte("bad password")) {
			err := errors.New("openvpn: management interface refused the password")
			m.closeLocked()
			return err
		}
		if len(buf) > 4096 {
			buf = buf[len(buf)-64:]
		}
	}
}

func deadlineFrom(ctx context.Context, fallback time.Duration) time.Time {
	if ctx == nil {
		return time.Now().Add(fallback)
	}
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Now().Add(fallback)
}

// Exec runs one management command and returns the reply with the `>` prompt
// stripped. Lines that are asynchronous notifications (they start with `>`)
// are kept out of the reply — they are not an answer to this command.
func (m *Management) Exec(ctx context.Context, cmd string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	if m.conn == nil {
		if err := m.dialLocked(ctx); err != nil {
			return "", err
		}
	}
	if err := m.conn.SetDeadline(deadlineFrom(ctx, mgmtTimeout)); err != nil {
		m.closeLocked()
		return "", err
	}
	if _, err := io.WriteString(m.conn, cmd+"\n"); err != nil {
		m.closeLocked()
		return "", fmt.Errorf("openvpn: management write %q: %w", cmd, err)
	}

	var out []string
	for {
		line, err := m.reader.ReadString('\n')
		if err != nil {
			m.closeLocked()
			return "", fmt.Errorf("openvpn: management read after %q: %w", cmd, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == ">" {
			break
		}
		if strings.HasPrefix(line, ">") {
			// Async notification (">CLIENT:…", ">HOLD:…"), not the reply.
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n"), nil
}

// Kill ends the live session whose common name is name.
//
// Common name == the panel's user id (username-as-common-name, LEGACY-VPN.md
// 4a), so this is a per-user disconnect and nothing else.
func (m *Management) Kill(ctx context.Context, name string) error {
	if strings.ContainsAny(name, "\r\n") {
		return errors.New("openvpn: refusing to kill a common name containing a newline")
	}
	reply, err := m.Exec(ctx, "kill "+name)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(reply, "\n") {
		if strings.HasPrefix(line, "ERROR:") {
			return fmt.Errorf("openvpn: kill %q: %s", name, line)
		}
	}
	return nil
}

// killSessions best-effort disconnects several users. A failure is logged, not
// returned: the caller is changing the roster anyway, and the reason it must
// still try is that an orphaned session outlives the rules that used to bound
// it (LEGACY-VPN.md 4d).
func (o *OpenVPN) killSessions(ctx context.Context, names []string) {
	m := o.Management()
	if m == nil {
		return
	}
	for _, name := range names {
		kctx, cancel := context.WithTimeout(ctx, mgmtTimeout)
		err := m.Kill(kctx, name)
		cancel()
		if err != nil && !errors.Is(err, context.Canceled) {
			logf("openvpn: disconnect of %q failed: %v", name, err)
		}
	}
}

// Session is one connected client as `status 2` reports it.
type Session struct {
	CommonName    string
	VirtualAddr   string
	BytesReceived int64
	BytesSent     int64
}

// Sessions returns the connected clients, keyed by common name (the panel's
// user id). The header row is parsed rather than the column numbers being
// hard-coded: 2.4, 2.5 and 2.6 do not have the same column list.
func (m *Management) Sessions(ctx context.Context) (map[string]Session, error) {
	reply, err := m.Exec(ctx, "status 2")
	if err != nil {
		return nil, err
	}
	idx := map[string]int{}
	out := map[string]Session{}
	for _, line := range strings.Split(reply, "\n") {
		fields := strings.Split(line, ",")
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "HEADER":
			if len(fields) > 1 && fields[1] == "CLIENT_LIST" {
				for i, name := range fields[2:] {
					idx[name] = i
				}
			}
		case "CLIENT_LIST":
			at := func(name string) int {
				i, ok := idx[name]
				if !ok || i+1 >= len(fields)-1 {
					return -1
				}
				return i + 1
			}
			cn := at("Common Name")
			if cn < 0 || fields[cn] == "" {
				continue
			}
			s := Session{CommonName: fields[cn]}
			if i := at("Virtual Address"); i >= 0 {
				s.VirtualAddr = fields[i]
			}
			if i := at("Bytes Received"); i >= 0 {
				s.BytesReceived, _ = strconv.ParseInt(fields[i], 10, 64)
			}
			if i := at("Bytes Sent"); i >= 0 {
				s.BytesSent, _ = strconv.ParseInt(fields[i], 10, 64)
			}
			out[s.CommonName] = s
		}
	}
	return out, nil
}

// readManagementPassword loads the password the node wrote for openvpn. It is
// only ever compared, written to its own 0600 file and used to authenticate —
// it is never logged and never returned.
func readManagementPassword(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("openvpn: reading management password: %w", err)
	}
	pw := strings.TrimRight(string(data), "\r\n")
	if pw == "" {
		return "", errors.New("openvpn: management password file is empty")
	}
	return pw, nil
}
