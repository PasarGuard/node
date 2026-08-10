package rest

import "net/http"

func (s *Service) GetLogs(w http.ResponseWriter, r *http.Request) {
	_, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	if err := disableWriteDeadline(w); err != nil {
		http.Error(w, "Streaming deadline control unsupported", http.StatusInternalServerError)
		return
	}
	stopContextWrites := stopWritesOnContext(r.Context(), w)
	defer stopContextWrites()

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

			if err := writeLogLine(r.Context(), w, log, responseWriteTimeout); err != nil {
				return
			}

		case <-r.Context().Done():
			return
		}
	}
}
