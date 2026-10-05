package rest

import (
	"fmt"
	"net/http"
)

// GetLogs multiplexes every running core's log channel; each line is prefixed
// with its core id so the client can tell them apart (CONTRACT §3.1). A
// single-core node emits the same lines it always did, prefixed with "1".
func (s *Service) GetLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	sources := s.LogSources()
	if len(sources) == 0 {
		http.Error(w, "backend not initialized", http.StatusServiceUnavailable)
		return
	}

	type tagged struct {
		coreID uint64
		line   string
	}
	merged := make(chan tagged, len(sources))

	for _, src := range sources {
		go func(coreID uint64, ch <-chan string) {
			for line := range ch {
				select {
				case merged <- tagged{coreID: coreID, line: line}:
				case <-r.Context().Done():
					return
				}
			}
			// A closed core channel must not end the multiplexed stream.
			select {
			case merged <- tagged{coreID: coreID}:
			case <-r.Context().Done():
			}
		}(src.ID, src.Backend.Logs())
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	for {
		select {
		case msg := <-merged:
			if msg.line == "" {
				continue
			}
			if _, err := fmt.Fprintf(w, "%d %s\n", msg.coreID, msg.line); err != nil {
				return
			}
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}
