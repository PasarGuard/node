package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
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

// mgmtQuiet is how long a ">" that is not newline-terminated has to stay alone
// before it is taken for the prompt.
//
// This is the difficulty of the protocol: the banner line starts with ">", so
// at the instant the reader has consumed "\n>" it cannot yet tell a prompt from
// the first two bytes of ">INFO:…". When the prompt arrives as a line of its
// own — which is what line-oriented parsing detects unambiguously — the quiet
// window is never consulted; it only arbitrates the newline-less form, on a
// local socket where "more data is already in flight" and "nothing more is
// coming" are microseconds apart.
const mgmtQuiet = 300 * time.Millisecond

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
// Two measured traps, both from LEGACY-VPN.md 3 (D0/D3c):
//   - with a pw-file configured, openvpn writes `ENTER PASSWORD:` and NOTHING
//     else — no newline. A line-based reader blocks until its timeout and the
//     interface looks dead, so the prompt for the password is matched as bytes;
//   - `management /path unix` is the working syntax; `management unix /path`
//     is not.
func (m *Management) dialLocked(ctx context.Context) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", m.socket)
	if err != nil {
		return fmt.Errorf("openvpn: management socket %s: %w", m.socket, err)
	}
	m.conn = conn
	m.reader = bufio.NewReader(conn)

	// The loop scans before it reads, so a byte that was already in hand —
	// one the quiet-period peek took out of the stream — is processed without
	// blocking for a next byte that may never come.
	var buf []byte
	var seen []string
	sent := false
	for {
		if !sent && bytes.Contains(buf, []byte("ENTER PASSWORD:")) {
			if _, err := conn.Write([]byte(m.password + "\n")); err != nil {
				m.closeLocked()
				return fmt.Errorf("openvpn: management password: %w", err)
			}
			sent = true
			buf = buf[:0]
			continue
		}
		if bytes.Contains(buf, []byte("ERROR:")) || bytes.Contains(buf, []byte("bad password")) {
			m.closeLocked()
			return errors.New("openvpn: management interface refused the password")
		}
		// A newline-terminated prompt is a line that is exactly ">" — and that
		// is the one shape the banner (">INFO:…") can never have.
		for {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			line := bytes.TrimRight(buf[:i], "\r")
			buf = buf[i+1:]
			if bytes.Equal(line, []byte(">")) {
				return nil
			}
			seen = append(seen, string(line))
			if len(seen) > 8 {
				seen = seen[len(seen)-8:]
			}
		}
		// The prompt may arrive with no trailing newline. Only then does the
		// buffer hold a bare ">" and does the quiet period get to arbitrate.
		if bytes.Equal(buf, []byte(">")) {
			peek, err := peekQuiet(m.reader, conn)
			if err != nil {
				m.closeLocked()
				return fmt.Errorf("openvpn: management handshake: %w", err)
			}
			if len(peek) == 0 {
				return nil
			}
			buf = append(buf, peek...)
			continue
		}
		// 2.6.19 answers the banner and then sends *no* prompt at all until a
		// command arrives (measured: "SUCCESS: password is correct", the
		// ">INFO:" line, then silence). Once at least one post-auth line has
		// been consumed, a quiet window is the end of the banner.
		if sent && len(seen) > 0 {
			peek, err := peekQuiet(m.reader, conn)
			if err != nil {
				m.closeLocked()
				return fmt.Errorf("openvpn: management handshake: %w", err)
			}
			if len(peek) == 0 {
				return nil
			}
			buf = append(buf, peek...)
			continue
		}
		if len(buf) > 4096 {
			buf = buf[len(buf)-64:]
		}
		if err := setDeadline(conn, ctx, mgmtTimeout); err != nil {
			m.closeLocked()
			return err
		}
		b, err := readByte(m.reader)
		if err != nil {
			m.closeLocked()
			return fmt.Errorf("openvpn: management handshake: %w (sent=%v buf=%q seen=%q)", err, sent, buf, seen)
		}
		buf = append(buf, b)
	}
}

// readByte reads exactly one byte at the caller's deadline.
func readByte(r *bufio.Reader) (byte, error) {
	b := make([]byte, 1)
	if _, err := r.Read(b); err != nil {
		return 0, err
	}
	return b[0], nil
}

// peekQuiet waits mgmtQuiet for one more byte. An empty result means the
// window elapsed with nothing: the ">" was the prompt.
func peekQuiet(r *bufio.Reader, conn net.Conn) ([]byte, error) {
	if err := conn.SetReadDeadline(time.Now().Add(mgmtQuiet)); err != nil {
		return nil, err
	}
	b, err := readByte(r)
	if err != nil {
		if isTimeoutErr(err) {
			return nil, nil
		}
		return nil, err
	}
	return []byte{b}, nil
}

func setDeadline(conn net.Conn, ctx context.Context, fallback time.Duration) error {
	return conn.SetReadDeadline(deadlineFrom(ctx, fallback))
}

func deadlineFrom(ctx context.Context, fallback time.Duration) time.Time {
	if ctx != nil {
		if d, ok := ctx.Deadline(); ok {
			return d
		}
	}
	return time.Now().Add(fallback)
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Exec runs one management command and returns the reply with the prompt
// stripped. Asynchronous notifications (lines starting with `>`) are kept out
// of the reply — they are not an answer to this command.
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
	if err := setDeadline(m.conn, ctx, mgmtTimeout); err != nil {
		m.closeLocked()
		return "", err
	}
	if _, err := m.conn.Write([]byte(cmd + "\n")); err != nil {
		m.closeLocked()
		return "", fmt.Errorf("openvpn: management write %q: %w", cmd, err)
	}
	return m.readReply(ctx, cmd)
}

// readReply collects lines until the prompt.
//
// The prompt may be sent without a trailing newline, so a plain line reader
// would hold the deadline open on every command. Once the reply has started
// flowing the window shrinks to mgmtQuiet: the prompt arrives in the same
// write as the last line, so a pause that long with a lone ">" buffered can
// only be the end of the answer.
func (m *Management) readReply(ctx context.Context, cmd string) (string, error) {
	var out []string
	var raw []string
	readAny := false
	for {
		dl := deadlineFrom(ctx, mgmtTimeout)
		if readAny {
			if q := time.Now().Add(mgmtQuiet); q.Before(dl) {
				dl = q
			}
		}
		if err := m.conn.SetReadDeadline(dl); err != nil {
			m.closeLocked()
			return "", err
		}
		line, err := m.reader.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")
		if err != nil {
			if isTimeoutErr(err) && (trimmed == ">" || readAny) {
				return strings.Join(out, "\n"), nil
			}
			if trimmed != "" {
				raw = append(raw, trimmed)
			}
			m.closeLocked()
			return "", fmt.Errorf("openvpn: management read after %q: %w (raw=%q)", cmd, err, raw)
		}
		if trimmed == "" {
			continue // the newline the handshake may have left behind
		}
		if trimmed == ">" {
			if readAny {
				return strings.Join(out, "\n"), nil
			}
			continue // a banner prompt left over from the handshake, not the reply
		}
		readAny = true
		raw = append(raw, trimmed)
		if strings.HasPrefix(trimmed, ">") {
			// Async notification (">CLIENT:…", ">HOLD:…"), not the reply.
			continue
		}
		out = append(out, trimmed)
		switch {
		case trimmed == "END":
			return strings.Join(out, "\n"), nil
		case strings.HasPrefix(trimmed, "SUCCESS:"), strings.HasPrefix(trimmed, "ERROR:"):
			return strings.Join(out, "\n"), nil
		}
	}
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
// user id). The header row gives the column positions rather than hard-coded
// indices: 2.4, 2.5 and 2.6 do not have the same column list, and a fixed index
// would silently read the wrong field instead of failing.
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
				// The header row carries two leading fields (HEADER, CLIENT_LIST) that
				// a CLIENT_LIST row does not, so a column ordinal taken from the
				// header is one less than its index in the data row.
				for i, name := range fields[2:] {
					idx[name] = i
				}
			}
		case "CLIENT_LIST":
			at := func(name string) int {
				i, ok := idx[name]
				if !ok || i+1 >= len(fields) {
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
// only ever written to its own 0600 file and used to authenticate — never
// logged, never returned.
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
