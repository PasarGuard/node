package rest

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

func (s *Service) validateApiKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKeyHeader := r.Header.Get("x-api-key")
		if apiKeyHeader == "" {
			http.Error(w, "missing x-api-key header", http.StatusUnauthorized)
			return
		}

		// check API key
		apiKey := s.ApiKey()

		key, err := uuid.Parse(apiKeyHeader)
		switch {
		case err != nil:
			http.Error(w, "invalid api key format: must be a valid UUID", http.StatusUnprocessableEntity)
			return
		case key != apiKey:
			http.Error(w, "api key mismatch", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// checkBackendMiddleware gates on the default core (core 1), which is what a
// node with one core has always had.
//
// A REST request names its core in the protobuf body, not in a path or header,
// so this middleware cannot see a core_id without consuming the body — and the
// body reader is not rewindable. The per-core routing therefore happens in the
// handlers that own their request message (rest.GetStats, rest.GetUserOnlineStat,
// rest.GetUserOnlineIpListStats), which resolve the core they were asked about
// and already return 503 "core N is not running" for a core that is not. What
// this gate keeps is the case that has always been here: no core has ever
// started, so there is nothing to talk to at all.
//
// ponytail: this leaves /stats/backend and /stats/system gated on the default
// core, because they answer from Empty, which names no core. They are the panel's
// node-level health probes (app/jobs/node_checker.py) and core_id 0 for them
// means exactly "the default core" on this transport, unchanged. A per-core
// variant of those two needs a route that can name a core, which is a Phase 2
// question — REST has no /events route either (CONTRACT §3.3).
func (s *Service) checkBackendMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		back := s.Backend()
		if back == nil {
			http.Error(w, "backend not initialized", http.StatusInternalServerError)
			return
		}
		if !back.Started() {
			http.Error(w, "core is not started yet", http.StatusServiceUnavailable)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		log.Printf("[API] New request from %s, %s, %s\n", r.RemoteAddr, r.Method, r.URL.Path)

		next.ServeHTTP(ww, r)

		log.Printf("[API] %s, %s, %s, %d\n", r.RemoteAddr, r.Method, r.URL.Path, ww.Status())
	})
}

func (s *Service) trackSuccessfulRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		// Only track successful requests (status codes 200-299)
		if status := ww.Status(); status >= 200 && status < 300 {
			s.NewRequest()
		}
	})
}
