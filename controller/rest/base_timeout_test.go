package rest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pasarguard/node/config"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func TestStopDisablesGlobalWriteTimeout(t *testing.T) {
	service := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodPut, "/stop", nil)

	service.Stop(w, r)

	if len(w.deadlines) == 0 || !w.deadlines[0].IsZero() {
		t.Fatalf("first write deadline = %v, want disabled deadline", w.deadlines)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestStartDisablesGlobalWriteTimeoutBeforeReadingRequest(t *testing.T) {
	service := New(config.NewTestConfig(t.TempDir(), uuid.New()))
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodPost, "/start", bytes.NewReader([]byte{0xff}))

	service.Start(w, r)

	if len(w.deadlines) == 0 || !w.deadlines[0].IsZero() {
		t.Fatalf("first write deadline = %v, want disabled deadline", w.deadlines)
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for empty protobuf body", w.Code)
	}
}
