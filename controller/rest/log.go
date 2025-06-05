package rest

import (
	"fmt"
	"net/http"
)

func (s *Service) GetLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	logChan := s.Backend().Logs()

	for {
		select {
		case log, ok := <-logChan:
			if !ok {
				return
			}

			_, err := fmt.Fprintf(w, "%s\n", log)
			if err != nil {
				return
			}

			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}
