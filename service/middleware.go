package service

import (
	"fmt"
	"github.com/go-chi/chi/v5/middleware"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"

	log "marzban-node/logger"
)

func (s *Service) checkSessionID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check ip
		clientIP := s.GetIP()
		clientID := s.GetSessionID()
		if clientIP == "" || clientID == uuid.Nil {
			http.Error(w, "please connect first", http.StatusTooEarly)
			return
		}

		// check ip
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if ip != s.GetIP() {
			http.Error(w, "IP address is not valid", http.StatusForbidden)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "please connect first", http.StatusUnauthorized)
			return
		}

		tokenString := strings.Split(authHeader, " ")[1]
		// check session id
		sessionID, err := uuid.Parse(tokenString)
		if err != nil {
			http.Error(w, "please send valid uuid", http.StatusUnprocessableEntity)
			return
		}

		if sessionID != clientID {
			http.Error(w, "Session ID mismatch.", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

//	func (s *Service) checkSessionIDAndReturnBody(next http.Handler) http.Handler {
//		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//			// check node is connected
//			clientIP := s.GetIP()
//			clientID := s.GetSessionID()
//			if clientIP == "" || clientID == uuid.Nil {
//				http.Error(w, "please connect first", http.StatusTooEarly)
//				return
//			}
//
//			// check ip
//			ip, _, err := net.SplitHostPort(r.RemoteAddr)
//			if err != nil {
//				http.Error(w, err.Error(), http.StatusBadRequest)
//				return
//			}
//			if ip != s.GetIP() {
//				http.Error(w, "IP address is not valid", http.StatusForbidden)
//				return
//			}
//
//			// check session id
//			var body requestBody
//			err = json.NewDecoder(r.Body).Decode(&body)
//			if err != nil {
//				log.Api(err, "  nobody")
//				http.Error(w, err.Error(), http.StatusPreconditionFailed)
//				return
//			}
//
//			sessionID, err := uuid.Parse(body.SessionId)
//			if err != nil {
//				http.Error(w, "please send valid uuid", http.StatusUnprocessableEntity)
//				return
//			}
//
//			if sessionID != clientID {
//				http.Error(w, "Session ID mismatch.", http.StatusForbidden)
//				return
//			}
//			log.Info(body)
//			ctx := context.WithValue(r.Context(), bodyKey{}, body)
//
//			next.ServeHTTP(w, r.WithContext(ctx))
//		})
//	}
func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		logMessage := fmt.Sprintf("%s, %s, %s, %d", r.RemoteAddr, r.Method, r.URL.Path, ww.Status())
		log.Api(logMessage)
	})
}
