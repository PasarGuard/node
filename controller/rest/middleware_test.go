package rest

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/config"
)

func newKeepAliveTestService(t *testing.T) (*Service, uuid.UUID) {
	t.Helper()
	key := uuid.New()
	s := New(config.NewTestConfig(t.TempDir(), key))
	t.Cleanup(s.Disconnect)
	return s, key
}

// Any request the panel makes proves the panel is alive, even one that fails
// or is still running, so keep-alive counts it when it arrives.
func TestKeepAliveRefreshedWhenAuthenticatedRequestArrives(t *testing.T) {
	s, key := newKeepAliveTestService(t)

	// A Start whose body is still uploading.
	body, upload := io.Pipe()
	defer upload.Close()
	req := httptest.NewRequest(http.MethodPost, "/start", body)
	req.Header.Set("x-api-key", key.String())
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.Router.ServeHTTP(rec, req)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for s.LastRequest().IsZero() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	refreshed := !s.LastRequest().IsZero()
	upload.CloseWithError(errors.New("panel went away"))
	<-done

	if !refreshed {
		t.Fatal("keep-alive was not refreshed while the request was in flight")
	}
	// The upload ended with an error ("panel went away"), so the handler
	// cannot read a body and answers 400.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestKeepAliveRefreshedForFailedRequests(t *testing.T) {
	for _, path := range []string{"/stats/backend", "/no/such/route"} {
		s, key := newKeepAliveTestService(t)

		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("x-api-key", key.String())
		rec := httptest.NewRecorder()
		s.Router.ServeHTTP(rec, req)

		if rec.Code < 400 {
			t.Fatalf("%s: status = %d, want an error", path, rec.Code)
		}
		if s.LastRequest().IsZero() {
			t.Fatalf("%s: keep-alive was not refreshed for an authenticated request that failed (%d)", path, rec.Code)
		}
	}
}

func TestKeepAliveNotRefreshedWithoutValidKey(t *testing.T) {
	s, _ := newKeepAliveTestService(t)

	for name, key := range map[string]string{
		"no key":     "",
		"not a uuid": "not-a-uuid",
		"wrong key":  uuid.NewString(),
	} {
		req := httptest.NewRequest(http.MethodGet, "/info", nil)
		if key != "" {
			req.Header.Set("x-api-key", key)
		}
		rec := httptest.NewRecorder()
		s.Router.ServeHTTP(rec, req)

		if rec.Code < 400 {
			t.Fatalf("%s: status = %d, want an auth error", name, rec.Code)
		}
		if !s.LastRequest().IsZero() {
			t.Fatalf("%s: an unauthenticated request refreshed keep-alive", name)
		}
	}
}

func TestKeepAliveRefreshedWhenLongRequestEnds(t *testing.T) {
	s, _ := newKeepAliveTestService(t)

	var atArrival time.Time
	handler := s.trackRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atArrival = s.LastRequest()
		time.Sleep(10 * time.Millisecond)
		http.Error(w, "client went away", http.StatusInternalServerError)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/logs", nil))

	if atArrival.IsZero() {
		t.Fatal("keep-alive was not refreshed when the request arrived")
	}
	if !s.LastRequest().After(atArrival) {
		t.Fatal("keep-alive was not refreshed when the request ended")
	}
}
