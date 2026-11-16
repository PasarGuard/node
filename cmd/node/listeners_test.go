package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller/rest"
	"github.com/pasarguard/node/controller/rpc"
	"github.com/pasarguard/node/pkg/tlsutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func listenerAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestListenerTransports(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		name := "private backend"
		if enabled {
			name = "TLS"
		}
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{TLSEnabled: enabled, ApiKey: uuid.New(), GeneratedConfigPath: t.TempDir(), LogBufferSize: 10}
			var serverTLS *tls.Config
			client := &http.Client{Timeout: 3 * time.Second}
			scheme := "http"
			var creds credentials.TransportCredentials = insecure.NewCredentials()
			if enabled {
				var err error
				serverTLS, err = tlsutil.LoadTLSCredentials("../../certs/ssl_cert.pem", "../../certs/ssl_key.pem")
				if err != nil {
					t.Fatal(err)
				}
				pool, err := tlsutil.LoadClientPool("../../certs/ssl_cert.pem")
				if err != nil {
					t.Fatal(err)
				}
				client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
				creds = credentials.NewTLS(&tls.Config{RootCAs: pool})
				scheme = "https"
			}
			addr := listenerAddress(t)
			stop, service, err := rest.StartHttpListener(serverTLS, addr, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer service.Disconnect()
			defer stop(context.Background())
			for _, auth := range []bool{false, true} {
				req, _ := http.NewRequest("GET", scheme+"://"+addr+"/info", nil)
				if auth {
					req.Header.Set("x-api-key", cfg.ApiKey.String())
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				want := http.StatusUnauthorized
				if auth {
					want = http.StatusOK
				}
				if resp.StatusCode != want {
					t.Fatalf("REST auth=%v: got %d", auth, resp.StatusCode)
				}
			}
			client.CloseIdleConnections()
			addr = listenerAddress(t)
			stopRPC, serviceRPC, err := rpc.StartGRPCListener(serverTLS, addr, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer serviceRPC.Disconnect()
			defer stopRPC(context.Background())
			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			c := common.NewNodeServiceClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := c.GetBaseInfo(ctx, &common.Empty{}); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("gRPC missing key: %v", err)
			}
			authCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("x-api-key", cfg.ApiKey.String()))
			if _, err := c.GetBaseInfo(authCtx, &common.Empty{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestListenersRejectUnsafePlaintext(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		cfg := &config.Config{TLSEnabled: enabled}
		addr := "0.0.0.0:0"
		if enabled {
			addr = "127.0.0.1:0"
		}
		if _, _, err := rest.StartHttpListener(nil, addr, cfg); err == nil {
			t.Fatal("REST allowed unsafe plaintext")
		}
		if _, _, err := rpc.StartGRPCListener(nil, addr, cfg); err == nil {
			t.Fatal("gRPC allowed unsafe plaintext")
		}
	}
}
