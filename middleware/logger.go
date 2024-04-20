package middleware

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	log "marzban-node/logger"
)

func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		logMessage := fmt.Sprintf("%s, %s, %s, %d \n", r.RemoteAddr, r.Method, r.URL.Path, ww.Status())
		log.ApiLog(logMessage)
	})
}
