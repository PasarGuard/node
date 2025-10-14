package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller"
	"github.com/pasarguard/node/controller/rest"
	"github.com/pasarguard/node/controller/rpc"
	"github.com/pasarguard/node/tools"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	addr := fmt.Sprintf("%s:%d", cfg.NodeHost, cfg.ServicePort)

	tlsConfig, err := tools.LoadTLSCredentials(cfg.SslCertFile, cfg.SslKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting Node: v%s", controller.NodeVersion)

	var shutdownFunc func(ctx context.Context) error
	var service controller.Service

	if cfg.ServiceProtocol == "rest" {
		shutdownFunc, service, err = rest.StartHttpListener(tlsConfig, addr, cfg)
	} else {
		shutdownFunc, service, err = rpc.StartGRPCListener(tlsConfig, addr, cfg)
	}
	if err != nil {
		log.Fatal(err)
	}

	defer service.Disconnect()

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
