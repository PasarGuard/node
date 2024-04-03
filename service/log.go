package service

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func (s *Service) Logs(w http.ResponseWriter, r *http.Request) {
	sessionID, err := uuid.Parse(r.URL.Query().Get("session_id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if sessionID != s.SessionID {
		http.Error(w, "Session ID mismatch.", http.StatusForbidden)
		return
	}

	interval, err := strconv.ParseFloat(r.URL.Query().Get("interval"), 64)
	if err != nil {
		http.Error(w, "Invalid interval value.", http.StatusBadRequest)
		return
	}

	if interval > 10 {
		http.Error(w, "Interval must be more than 0 and at most 10 seconds.", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func(conn *websocket.Conn) {
		_ = conn.Close()
	}(conn)

	cache := ""
	lastSentTs := time.Now()
	logs := s.Core.GetLogs()
	for sessionID == s.SessionID {
		if interval > 0 && time.Since(lastSentTs).Seconds() >= interval && cache != "" {
			err = conn.WriteMessage(websocket.TextMessage, []byte(cache))
			if err != nil {
				break
			}
			cache = ""
			lastSentTs = time.Now()
		}

		if len(logs) == 0 {
			_, _, err = conn.ReadMessage()
			if err != nil {
				break
			}
			continue
		}

		log := logs[0]
		logs = logs[1:]

		if interval > 0 {
			cache += log + "\n"
			continue
		}

		err = conn.WriteMessage(websocket.TextMessage, []byte(log))
		if err != nil {
			break
		}
	}
}
