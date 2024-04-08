package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-chi/chi/v5"
	"marzban-node/certificate"
	"marzban-node/config"
	log "marzban-node/logger"
	"marzban-node/service"
	"net/http"
	"os"
)

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func createServer(addr string, r chi.Router) (server *http.Server) {

	serverCert, err := tls.LoadX509KeyPair(config.SslCertFile, config.SslKeyFile)
	if err != nil {
		log.ErrorLog("Failed to load server certificate and key: ", err)
	}

	clientCertPool := x509.NewCertPool()
	clientCert, err := os.ReadFile(config.SslClientCertFile)
	if err != nil {
		log.ErrorLog("Failed to read client certificate: ", err)
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
	config.InitConfig()
	certFileExists := fileExists(config.SslCertFile)
	keyFileExists := fileExists(config.SslKeyFile)
	if !certFileExists || !keyFileExists {
		certificate.RewriteSslFile()
	}
	sslClientCertFile := fileExists(config.SslClientCertFile)

	if !sslClientCertFile {
		panic("SSL_CLIENT_CERT_FILE is required for rest service.")
	}

	addr := fmt.Sprintf("%s:%d", config.NodeHost, config.ServicePort)
	s := service.NewService()

	server := createServer(addr, s.Router)

	// Start server with TLS
	log.InfoLog("Server is listening on " + addr)
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		log.ErrorLog("Failed to start server: ", err)
	}
}
