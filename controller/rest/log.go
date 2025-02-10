package rest

import (
	"net/http"
	"time"

	"github.com/m03ed/marzban-node-go/common"
	"github.com/m03ed/marzban-node-go/config"
)

func (s *Service) sendLogs(w http.ResponseWriter, logs []string, status int) {
	w.WriteHeader(status)
	common.SendProtoResponse(w, &common.LogList{
		Logs: logs,
	})
}

func (s *Service) GetLogs(w http.ResponseWriter, r *http.Request) {
	logs := make([]string, 0, config.MaxLogPerRequest)
	logChan := s.controller.GetBackend().GetLogs()
	timeout := time.After(60 * time.Second)
	counter := 0

	ticker := time.NewTicker(100 * time.Millisecond) // Periodic check every 100ms
	defer ticker.Stop()

	for {
		select {
		case log, ok := <-logChan:
			if !ok { // If the channel is closed, break the loop
				s.sendLogs(w, logs, http.StatusInternalServerError)
			}

			// Add the log to the logs slice using the counter
			if counter < cap(logs) {
				logs = logs[:counter+1]
				logs[counter] = log
				counter++
			}

			if counter >= config.MaxLogPerRequest {
				// Send the collected logs immediately
				s.sendLogs(w, logs, http.StatusOK)
				return
			}
			continue

		case <-ticker.C:
			if len(logs) > 0 && len(logChan) == 0 {
				// If the cache is not empty and the channel is empty, send the logs
				s.sendLogs(w, logs, http.StatusOK)
				return
			}

		case <-timeout:
			if len(logs) > 0 {
				s.sendLogs(w, logs, http.StatusOK)
			} else {
				s.sendLogs(w, logs, http.StatusNoContent)
			}
			return

		case <-r.Context().Done(): // If the client disconnects or the request is canceled
			s.sendLogs(w, logs, http.StatusRequestTimeout)
			return
		}
	}
}
