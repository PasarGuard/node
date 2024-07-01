package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"marzban-node/tools"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"marzban-node/config"
	log "marzban-node/logger"
	"marzban-node/service"
)

func createServer(addr string, r chi.Router) (server *http.Server) {

	serverCert, err := tls.LoadX509KeyPair(config.SslCertFile, config.SslKeyFile)
	if err != nil {
		log.Error("Failed to load server certificate and key: ", err)
	}

	clientCertPool := x509.NewCertPool()
	clientCert, err := os.ReadFile(config.SslClientCertFile)
	if err != nil {
		log.Error("Failed to read client certificate: ", err)
	}
	clientCertPool.AppendCertsFromPEM(clientCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	server = &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
		Handler:   r,
	}
	return server
}

func main() {
	certFileExists := tools.FileExists(config.SslCertFile)
	keyFileExists := tools.FileExists(config.SslKeyFile)
	if !certFileExists || !keyFileExists {
		tools.RewriteSslFile()
	}
	sslClientCertFile := tools.FileExists(config.SslClientCertFile)

	if !sslClientCertFile {
		panic("SSL_CLIENT_CERT_FILE is required for rest service.")
	}

	addr := fmt.Sprintf("%s:%d", config.NodeHost, config.ServicePort)
	s, err := service.NewService()
	if err != nil {
		panic(err)
	}

	server := createServer(addr, s.Router)

	// Create a channel to listen for interrupt signals
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	// Start server with TLS
	go func() {
		log.Info("Server is listening on", addr)
		log.Info("Press Ctrl+C to stop")
		if err = server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Error("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	<-stopChan
	log.Info("Shutting down server...")

	// Create a context with timeout for the shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown the server gracefully
	if err = server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown: %v", err)
	}

	log.Info("Performing cleanup job...")

	s.StopJobs()

	// Add your cleanup code here
	log.Info("Server gracefully stopped")
}
