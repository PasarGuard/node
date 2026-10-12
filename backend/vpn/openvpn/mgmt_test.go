package openvpn

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

const fakeMgmtPassword = "0123456789abcdef0123456789abcdef"

// fakeManagement speaks the server side of the protocol as openvpn does,
// including the two traps the real interface is built on:
//
//   - `ENTER PASSWORD:` arrives with NO trailing newline, so a line-based
//     reader blocks until its timeout and the interface looks dead
//     (LEGACY-VPN.md 3 D0);
//   - the reply is terminated by a prompt line that is exactly ">", while
//     async notifications are ">"-prefixed lines that must not be mistaken
//     for an answer.
func fakeManagement(t *testing.T, socket string) {
	t.Helper()
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets unavailable here (%v); run on Linux to exercise the management client", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeManagement(conn)
		}
	}()
}

func serveFakeManagement(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	if _, err := conn.Write([]byte("ENTER PASSWORD:")); err != nil { // no newline, on purpose
		return
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	if strings.TrimRight(line, "\r\n") != fakeMgmtPassword {
		conn.Write([]byte("\nERROR: bad password\n"))
		return
	}
	// Exactly what OpenVPN 2.6.19 sends, byte for byte: the success line, the
	// version banner, and then silence — there is no ">" prompt anywhere in
	// this build (measured, see mgmt.go readReply).
	conn.Write([]byte("\nSUCCESS: password is correct\n" +
		">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n"))

	for {
		cmd, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd = strings.TrimRight(cmd, "\r\n")
		switch {
		case strings.HasPrefix(cmd, "kill "):
			name := strings.TrimPrefix(cmd, "kill ")
			if name == "ghost" {
				conn.Write([]byte("ERROR: common name 'ghost' not found\n"))
				continue
			}
			// An async notification in the middle of a reply: it must be
			// filtered out, not reported as part of the answer.
			conn.Write([]byte(">CLIENT:CONNECT,1,1\n"))
			conn.Write([]byte("SUCCESS: common name '" + name + "' found, 100/200 bytes r/w, 1/2 clients\n"))
		case cmd == "status 2":
			conn.Write([]byte(
				"TITLE,OpenVPN 2.6.19\n" +
					"HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID\n" +
					"CLIENT_LIST,1001,203.0.113.9:54000,10.8.0.2,,4096,8192,Fri Oct 12 00:00:00 2026,1760000000,1001,1,0\n" +
					"CLIENT_LIST,1002,203.0.113.10:54001,10.8.0.3,,100,200,Fri Oct 12 00:00:00 2026,1760000000,1002,2,0\n" +
					"GLOBAL_STATS,Max bcast/mcast queue length,0\n" +
					"GLOBAL_STATS,dco_enabled,0\n" +
					"END\n"))
		default:
			conn.Write([]byte("ERROR: unknown command, see 'help' for more information\n"))
		}
	}
}

func startFake(t *testing.T) *Management {
	t.Helper()
	socket := filepathJoin(t.TempDir(), "mgmt.sock")
	fakeManagement(t, socket)
	m := newManagement(socket, fakeMgmtPassword)
	t.Cleanup(m.Close)
	return m
}

func TestManagementHandshakeSurvivesTheNewlinelessPrompt(t *testing.T) {
	m := startFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reply, err := m.Exec(ctx, "status 2")
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !strings.Contains(reply, "TITLE,OpenVPN 2.6.19") {
		t.Errorf("reply = %q, want the status table", reply)
	}

	// The connection is reused for the next command rather than redialled.
	if _, err := m.Exec(ctx, "kill 1001"); err != nil {
		t.Fatalf("second Exec: %v", err)
	}
}

func TestManagementRejectsTheWrongPassword(t *testing.T) {
	socket := filepathJoin(t.TempDir(), "mgmt.sock")
	fakeManagement(t, socket)
	m := newManagement(socket, "wrong-password")
	defer m.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := m.Exec(ctx, "status 2"); err == nil {
		t.Fatal("wrong password was accepted")
	}
	if m.conn != nil {
		t.Error("connection was left open after a refused password")
	}
}

// Async notifications are filtered out of a reply: a `>CLIENT:CONNECT` that
// lands between the command and its answer is not an answer.
func TestKillFiltersAsyncNotifications(t *testing.T) {
	m := startFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.Kill(ctx, "1001"); err != nil {
		t.Fatalf("kill 1001: %v", err)
	}
	// The error path: an unknown common name is reported, not swallowed.
	if err := m.Kill(ctx, "ghost"); err == nil {
		t.Error("kill of an unknown common name succeeded")
	}
	// A newline would let one kill become two commands.
	if err := m.Kill(ctx, "1001\nshutdown"); err == nil {
		t.Error("kill of a common name containing a newline was accepted")
	}
}

func TestSessionsParsesStatus2ByHeaderName(t *testing.T) {
	m := startFake(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sessions, err := m.Sessions(ctx)
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2: %+v", len(sessions), sessions)
	}
	s := sessions["1001"]
	if s.VirtualAddr != "10.8.0.2" {
		t.Errorf("1001 virtual address = %q, want 10.8.0.2", s.VirtualAddr)
	}
	if s.BytesReceived != 4096 || s.BytesSent != 8192 {
		t.Errorf("1001 bytes = %d/%d, want 4096/8192", s.BytesReceived, s.BytesSent)
	}
	if _, ok := sessions["ghost"]; ok {
		t.Error("a session that was never reported appeared in the map")
	}
}

// The seam accounting-quota drives must survive a child that never came up:
// nil-safe rather than a panic on the panel's health check path.
func TestSeamIsNilSafeBeforeStart(t *testing.T) {
	if _, err := os.Stat("openvpn.go"); err != nil {
		t.Skip(err)
	}
	// A zero value, exactly what New returns before anything is running.
	var o *OpenVPN
	if o.Management() != nil {
		t.Error("Management() on a nil backend must be nil")
	}
}

// filepathJoin keeps the test files free of a path/filepath import for one call.
func filepathJoin(dir, name string) string {
	return strings.TrimRight(dir, `/\`) + string(os.PathSeparator) + name
}
