package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/pkg/tlsutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Exercise the shipped nginx snippets in CI, including HTTP streaming and gRPC
// server streaming. Direct node listeners are covered by TestListenerTransports.
func TestNginxTLSFrontends(t *testing.T) {
	nginx := os.Getenv("NODE_TEST_NGINX")
	if nginx == "" {
		t.Skip("set NODE_TEST_NGINX to enable the nginx deployment tests")
	}
	for _, protocol := range []string{"rest", "grpc"} {
		t.Run(protocol, func(t *testing.T) {
			backendAddr, maintenanceAddr := listenerAddress(t), listenerAddress(t)
			frontendAddr, maintenanceFrontend := listenerAddress(t), listenerAddress(t)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("x-api-key") != "proxy-test-key" {
					http.Error(w, "missing key", 401)
					return
				}
				if r.URL.Path == "/logs" {
					fmt.Fprintln(w, "stream ready")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				fmt.Fprintln(w, `{"status":"ok"}`)
			})
			startHTTP := func(addr string) {
				l, err := net.Listen("tcp", addr)
				if err != nil {
					t.Fatal(err)
				}
				s := &http.Server{Handler: handler}
				go s.Serve(l)
				t.Cleanup(func() { s.Close() })
			}
			startHTTP(maintenanceAddr)
			if protocol == "rest" {
				startHTTP(backendAddr)
			} else {
				l, err := net.Listen("tcp", backendAddr)
				if err != nil {
					t.Fatal(err)
				}
				s := grpc.NewServer()
				common.RegisterNodeServiceServer(s, proxyStreamService{})
				go s.Serve(l)
				t.Cleanup(s.Stop)
			}
			snippet, err := os.ReadFile("../../examples/nginx/" + protocol + ".conf")
			if err != nil {
				t.Fatal(err)
			}
			cert, _ := filepath.Abs("../../certs/ssl_cert.pem")
			key, _ := filepath.Abs("../../certs/ssl_key.pem")
			_, frontendPort, _ := net.SplitHostPort(frontendAddr)
			_, maintenancePort, _ := net.SplitHostPort(maintenanceFrontend)
			snippetText := strings.NewReplacer(
				"127.0.0.1:62150", backendAddr, "127.0.0.1:62151", maintenanceAddr,
				"listen 62050 ", "listen 127.0.0.1:"+frontendPort+" ",
				"listen 62051 ", "listen 127.0.0.1:"+maintenancePort+" ",
				"/etc/pg-node-tls/fullchain.pem", cert, "/etc/pg-node-tls/privkey.pem", key,
			).Replace(string(snippet))
			dir := t.TempDir()
			configPath := filepath.Join(dir, "nginx.conf")
			configText := "daemon off; master_process off; error_log stderr; pid " + dir + "/nginx.pid; events {} http { access_log off; client_body_temp_path " + dir + "/body; proxy_temp_path " + dir + "/proxy; " + snippetText + " }"
			if err := os.WriteFile(configPath, []byte(configText), 0600); err != nil {
				t.Fatal(err)
			}
			logFile, err := os.Create(filepath.Join(dir, "nginx.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer logFile.Close()
			cmd := exec.Command(nginx, "-p", dir, "-c", configPath)
			cmd.Stdout, cmd.Stderr = logFile, logFile
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
			deadline := time.Now().Add(5 * time.Second)
			for {
				conn, err := net.DialTimeout("tcp", maintenanceFrontend, 100*time.Millisecond)
				if err == nil {
					conn.Close()
					break
				}
				if time.Now().After(deadline) {
					data, _ := os.ReadFile(logFile.Name())
					t.Fatalf("nginx did not start: %s", data)
				}
				time.Sleep(20 * time.Millisecond)
			}
			pool, err := tlsutil.LoadClientPool(cert)
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
			defer client.CloseIdleConnections()
			checkHTTP := func(addr, path string, auth bool) {
				req, _ := http.NewRequest("GET", "https://"+addr+path, nil)
				if auth {
					req.Header.Set("x-api-key", "proxy-test-key")
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				want := 401
				if auth {
					want = 200
				}
				if resp.StatusCode != want {
					t.Fatalf("HTTP %s: %d", path, resp.StatusCode)
				}
				if path == "/logs" && auth {
					line, err := bufio.NewReader(resp.Body).ReadString('\n')
					if err != nil || line != "stream ready\n" {
						t.Fatalf("stream buffering: %q %v", line, err)
					}
				}
			}
			checkHTTP(maintenanceFrontend, "/", false)
			checkHTTP(maintenanceFrontend, "/", true)
			if protocol == "rest" {
				checkHTTP(frontendAddr, "/", false)
				checkHTTP(frontendAddr, "/", true)
				checkHTTP(frontendAddr, "/logs", true)
			} else {
				conn, err := grpc.NewClient(frontendAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool})))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				client := common.NewNodeServiceClient(conn)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				stream, err := client.GetLogs(ctx, &common.Empty{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
					t.Fatalf("gRPC stream auth: %v", err)
				}
				authCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("x-api-key", "proxy-test-key"))
				stream, err = client.GetLogs(authCtx, &common.Empty{})
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 3; i++ {
					log, err := stream.Recv()
					if err != nil || log.Detail != fmt.Sprint(i) {
						t.Fatalf("gRPC stream %d: %v %v", i, log, err)
					}
				}
			}
		})
	}
}

type proxyStreamService struct {
	common.UnimplementedNodeServiceServer
}

func (proxyStreamService) GetLogs(_ *common.Empty, stream common.NodeService_GetLogsServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	keys := md.Get("x-api-key")
	if len(keys) == 0 || keys[0] != "proxy-test-key" {
		return status.Error(codes.Unauthenticated, "missing key")
	}
	for i := 0; i < 3; i++ {
		if err := stream.Send(&common.Log{Detail: fmt.Sprint(i)}); err != nil {
			return err
		}
	}
	return nil
}
