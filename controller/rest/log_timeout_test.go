package rest

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

type pipeResponseWriter struct {
	conn   net.Conn
	header http.Header
}

type cancelOnDeadlineWriter struct {
	header      http.Header
	cancel      context.CancelFunc
	deadlineSet int
	wrote       bool
}

func (w *cancelOnDeadlineWriter) Header() http.Header { return w.header }
func (w *cancelOnDeadlineWriter) WriteHeader(int)     {}
func (w *cancelOnDeadlineWriter) Write(payload []byte) (int, error) {
	w.wrote = true
	return len(payload), nil
}
func (w *cancelOnDeadlineWriter) SetWriteDeadline(time.Time) error {
	w.deadlineSet++
	if w.deadlineSet == 1 {
		w.cancel()
	}
	return nil
}

func newPipeResponseWriter(conn net.Conn) *pipeResponseWriter {
	return &pipeResponseWriter{conn: conn, header: make(http.Header)}
}

func (w *pipeResponseWriter) Header() http.Header {
	return w.header
}

func (w *pipeResponseWriter) Write(payload []byte) (int, error) {
	return w.conn.Write(payload)
}

func (w *pipeResponseWriter) WriteHeader(int) {}

func (w *pipeResponseWriter) Flush() {}

func (w *pipeResponseWriter) SetWriteDeadline(deadline time.Time) error {
	return w.conn.SetWriteDeadline(deadline)
}

func wrappedPipeResponseWriter(conn net.Conn) http.ResponseWriter {
	w := middleware.NewWrapResponseWriter(newPipeResponseWriter(conn), 1)
	return middleware.NewWrapResponseWriter(w, 1)
}

func writeAndReadLogLine(t *testing.T, w http.ResponseWriter, reader net.Conn, line string, timeout time.Duration) {
	t.Helper()

	want := []byte(line + "\n")
	readResult := make(chan error, 1)
	go func() {
		if err := reader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			readResult <- err
			return
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(reader, got); err != nil {
			readResult <- err
			return
		}
		if string(got) != string(want) {
			readResult <- errors.New("unexpected log line")
			return
		}
		readResult <- nil
	}()

	if err := writeLogLine(context.Background(), w, line, timeout); err != nil {
		t.Fatalf("write log line: %v", err)
	}
	if err := <-readResult; err != nil {
		t.Fatalf("read log line: %v", err)
	}
}

func TestLogStreamSurvivesIdlePeriodsPastWriteTimeout(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	w := wrappedPipeResponseWriter(serverConn)
	timeout := 50 * time.Millisecond
	if err := serverConn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("set initial server deadline: %v", err)
	}
	if err := disableWriteDeadline(w); err != nil {
		t.Fatalf("disable idle write deadline: %v", err)
	}

	time.Sleep(3 * timeout)
	writeAndReadLogLine(t, w, clientConn, "after initial idle", timeout)

	// A successful write must clear its sliding deadline while the handler waits
	// for the next log entry.
	time.Sleep(3 * timeout)
	writeAndReadLogLine(t, w, clientConn, "after second idle", timeout)
}

func TestLogStreamBoundsStalledReader(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	timeout := 50 * time.Millisecond
	started := time.Now()
	err := writeLogLine(context.Background(), wrappedPipeResponseWriter(serverConn), "blocked", timeout)
	elapsed := time.Since(started)

	if err == nil {
		t.Fatal("write unexpectedly succeeded with a stalled reader")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("write error = %v, want network timeout", err)
	}
	if elapsed > 10*timeout {
		t.Fatalf("stalled write took %v, want at most %v", elapsed, 10*timeout)
	}
}

func TestLogStreamCancelsStalledWriteWithRequestContext(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	w := wrappedPipeResponseWriter(serverConn)
	stopContextWrites := stopWritesOnContext(ctx, w)
	defer stopContextWrites()
	time.AfterFunc(50*time.Millisecond, cancel)
	started := time.Now()
	err := writeLogLine(ctx, w, "blocked", time.Second)
	elapsed := time.Since(started)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("write error = %v, want context.Canceled", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("canceled write took %v, want at most 500ms", elapsed)
	}
}

func TestLogStreamCancellationCannotBeOverwrittenBySlidingDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := &cancelOnDeadlineWriter{header: make(http.Header), cancel: cancel}

	err := writeLogLine(ctx, w, "must not be written", time.Second)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("write error = %v, want context.Canceled", err)
	}
	if w.wrote {
		t.Fatal("write started after cancellation raced with the sliding deadline")
	}
	if w.deadlineSet != 2 {
		t.Fatalf("deadline updates = %d, want sliding deadline followed by immediate cancellation", w.deadlineSet)
	}
}

func TestHTTPServerKeepsWriteTimeoutForRegularResponses(t *testing.T) {
	server := newHTTPServer(nil, "127.0.0.1:0", http.NotFoundHandler())
	if server.WriteTimeout != responseWriteTimeout {
		t.Fatalf("WriteTimeout = %v, want %v", server.WriteTimeout, responseWriteTimeout)
	}
}
