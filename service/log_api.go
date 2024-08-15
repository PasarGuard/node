package service

import (
	"encoding/json"
	"net/http"
	"time"
)

//var upgrader = websocket.Upgrader{
//	ReadBufferSize:  1024,
//	WriteBufferSize: 1024,
//}

//func (s *Service) Logs(w http.ResponseWriter, r *http.Request) {
//	interval, err := strconv.ParseFloat(r.URL.Query().Get("interval"), 64)
//	if err != nil {
//		http.Error(w, "Invalid interval value.", http.StatusBadRequest)
//		return
//	}
//
//	if interval > 10 && interval > 0 {
//		http.Error(w, "Interval must be more than 0 and at most 10 seconds.", http.StatusBadRequest)
//		return
//	}
//
//	conn, err := upgrader.Upgrade(w, r, nil)
//	if err != nil {
//		http.Error(w, err.Error(), http.StatusInternalServerError)
//		return
//	}
//	defer func(conn *websocket.Conn) {
//		_ = conn.Close()
//	}(conn)
//
//	cache := ""
//	lastSentTs := time.Now()
//	logChan := s.GetCore().GetLogs()
//
//	for {
//		if interval > 0 && time.Since(lastSentTs).Seconds() >= interval && cache != "" {
//			err = conn.WriteMessage(websocket.TextMessage, []byte(cache))
//			if err != nil {
//				break
//			}
//			cache = ""
//			lastSentTs = time.Now()
//		}
//
//		log := <-logChan
//		if len(log) == 0 {
//			_, _, err = conn.ReadMessage()
//			if err != nil {
//				break
//			}
//			continue
//		}
//
//		if interval > 0 {
//			cache += log + "\n"
//			continue
//		}
//
//		err = conn.WriteMessage(websocket.TextMessage, []byte(log))
//		if err != nil {
//			break
//		}
//	}
//}

func (s *Service) Logs(w http.ResponseWriter, r *http.Request) {
	cache := ""
	logChan := s.GetCore().GetLogs()
	timeout := time.After(60 * time.Second)
	counter := 0

	ticker := time.NewTicker(100 * time.Millisecond) // Periodic check every 100ms
	defer ticker.Stop()

	for {
		select {
		case log, ok := <-logChan:
			if !ok { // If the channel is closed, break the loop
				break
			}
			// Append the log to the cache with a newline
			cache += log + "\n"
			counter++

			if counter >= 100 {
				// Send the collected logs immediately
				w.Header().Set("Content-Type", "text/plain")
				json.NewEncoder(w).Encode(cache)
				return
			}
			continue

		case <-ticker.C:
			if len(cache) > 0 && len(logChan) == 0 {
				// If the cache is not empty and the channel is empty, send the logs
				w.Header().Set("Content-Type", "text/plain")
				json.NewEncoder(w).Encode(cache)
				return
			}

		case <-timeout:
			if len(cache) > 0 {
				w.Header().Set("Content-Type", "text/plain")
				json.NewEncoder(w).Encode(cache)
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
			return

		case <-r.Context().Done(): // If the client disconnects or the request is canceled
			w.WriteHeader(http.StatusRequestTimeout)
			return
		}
	}
}
