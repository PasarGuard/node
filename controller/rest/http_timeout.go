package rest

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

const responseWriteTimeout = 30 * time.Second

func newHTTPServer(tlsConfig *tls.Config, addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		TLSConfig:         tlsConfig,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      responseWriteTimeout,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
}

func disableWriteDeadline(w http.ResponseWriter) error {
	return http.NewResponseController(w).SetWriteDeadline(time.Time{})
}

func stopWritesOnContext(ctx context.Context, w http.ResponseWriter) func() {
	controller := http.NewResponseController(w)
	cancelDeadlineDone := make(chan struct{})
	stopCancelDeadline := context.AfterFunc(ctx, func() {
		_ = controller.SetWriteDeadline(time.Now())
		close(cancelDeadlineDone)
	})
	return func() {
		if !stopCancelDeadline() {
			<-cancelDeadlineDone
		}
	}
}

func writeLogLine(ctx context.Context, w http.ResponseWriter, line string, timeout time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	// Cancellation may race with the sliding deadline update above. Re-check
	// after setting it so an already-expired cancellation deadline can never be
	// overwritten by the longer per-write timeout.
	if err := ctx.Err(); err != nil {
		_ = controller.SetWriteDeadline(time.Now())
		return err
	}
	if _, err := fmt.Fprintf(w, "%s\n", line); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	if err := controller.Flush(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
	if err := controller.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	return ctx.Err()
}
