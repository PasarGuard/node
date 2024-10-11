package service

import (
	"encoding/json"
	"marzban-node/config"
	"net/http"
	"time"
)

type logResponse struct {
	Logs  []string `json:"logs,omitempty"`
	Error string   `json:"error,omitempty"`
}

func sendLogs(w http.ResponseWriter, logs []string, status int) {
	err := ""
	if status != http.StatusOK {
		err = http.StatusText(status)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logResponse{
		Logs:  logs,
		Error: err,
	})
}

func (s *Service) Logs(w http.ResponseWriter, r *http.Request) {
	core := s.GetCore()
	if !core.Started() {
		sendLogs(w, []string{}, http.StatusTooEarly)
	}
	logs := make([]string, 0, 100)
	logChan := core.GetLogs()
	timeout := time.After(60 * time.Second)
	counter := 0

	ticker := time.NewTicker(100 * time.Millisecond) // Periodic check every 100ms
	defer ticker.Stop()

	for {
		select {
		case log, ok := <-logChan:
			if !ok { // If the channel is closed, break the loop
				sendLogs(w, logs, http.StatusInternalServerError)
			}

			// Add the log to the logs slice using the counter
			if counter < cap(logs) {
				logs = logs[:counter+1]
				logs[counter] = log
				counter++
			}

			if counter >= config.MaxLogPerRequest {
				// Send the collected logs immediately
				sendLogs(w, logs, http.StatusOK)
				return
			}
			continue

		case <-ticker.C:
			if len(logs) > 0 && len(logChan) == 0 {
				// If the cache is not empty and the channel is empty, send the logs
				sendLogs(w, logs, http.StatusOK)
				return
			}

		case <-timeout:
			if len(logs) > 0 {
				sendLogs(w, logs, http.StatusOK)
			} else {
				sendLogs(w, logs, http.StatusNoContent)
			}
			return

		case <-r.Context().Done(): // If the client disconnects or the request is canceled
			sendLogs(w, logs, http.StatusRequestTimeout)
			return
		}
	}
}
