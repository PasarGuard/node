package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/m03ed/gozargah-node/config"
	"github.com/m03ed/gozargah-node/controller"
	"github.com/m03ed/gozargah-node/controller/rest"
	"github.com/m03ed/gozargah-node/controller/rpc"
	nodeLogger "github.com/m03ed/gozargah-node/logger"
	"github.com/m03ed/gozargah-node/tools"
)

func main() {
	nodeLogger.SetOutputMode(config.Debug)

	certFileExists := tools.FileExists(config.SslCertFile)
	keyFileExists := tools.FileExists(config.SslKeyFile)
	if !certFileExists || !keyFileExists {
		if err := tools.RewriteSslFile(config.SslCertFile, config.SslKeyFile); err != nil {
			log.Fatal(err)
		}
	}
	sslClientCertFile := tools.FileExists(config.SslClientCertFile)

	if !sslClientCertFile {
		log.Fatal("SSL_CLIENT_CERT_FILE is required.")
	}

	addr := fmt.Sprintf("%s:%d", config.NodeHost, config.ServicePort)

	tlsConfig, err := tools.LoadTLSCredentials(config.SslCertFile, config.SslKeyFile,
		config.SslClientCertFile, false)
	if err != nil {
		log.Fatal(err)
	}

	var shutdownFunc func(ctx context.Context) error
	var service controller.Service

	if config.ServiceProtocol == "rest" {
		shutdownFunc, service, err = rest.StartHttpListener(tlsConfig, addr)
	} else {
		shutdownFunc, service, err = rpc.StartGRPCListener(tlsConfig, addr)
	}

	defer service.StopService()

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	// Wait for interrupt
	<-stopChan
	log.Println("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err = shutdownFunc(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Server gracefully stopped")
}
