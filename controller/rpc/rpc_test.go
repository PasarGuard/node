package rpc

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/m03ed/gozargah-node/common"
	"github.com/m03ed/gozargah-node/config"
	nodeLogger "github.com/m03ed/gozargah-node/logger"
	"github.com/m03ed/gozargah-node/tools"
)

var (
	servicePort         = 8001
	nodeHost            = "127.0.0.1"
	xrayExecutablePath  = "/usr/local/bin/xray"
	xrayAssetsPath      = "/usr/local/share/xray"
	sslCertFile         = "../../certs/ssl_cert.pem"
	sslKeyFile          = "../../certs/ssl_key.pem"
	sslClientCertFile   = "../../certs/ssl_client_cert.pem"
	sslClientKeyFile    = "../../certs/ssl_client_key.pem"
	generatedConfigPath = "../../generated/"
	addr                = fmt.Sprintf("%s:%d", nodeHost, servicePort)
	configPath          = "../../backend/xray/config.json"
)

func TestGRPCConnection(t *testing.T) {
	config.SetEnv(servicePort, 0, nodeHost, xrayExecutablePath, xrayAssetsPath, sslCertFile,
		sslKeyFile, sslClientCertFile, "grpc", generatedConfigPath, true)

	nodeLogger.SetOutputMode(true)

	certFileExists := tools.FileExists(sslCertFile)
	keyFileExists := tools.FileExists(sslKeyFile)

	if !certFileExists || !keyFileExists {
		if err := tools.RewriteSslFile(sslCertFile, sslKeyFile); err != nil {
			t.Fatal(err)
		}
	}
	clientCertFileExists := tools.FileExists(sslClientCertFile)
	if !clientCertFileExists {
		t.Fatal("SSL_CLIENT_CERT_FILE is required.")
	}

	clientKeyFileExists := tools.FileExists(sslClientCertFile)
	if !clientKeyFileExists {
		t.Fatal("SSL_CLIENT_KEY_FILE is required.")
	}

	tlsConfig, err := tools.LoadTLSCredentials(sslCertFile, sslKeyFile, sslClientCertFile, false)
	if err != nil {
		t.Fatal(err)
	}

	shutdownFunc, s, err := StartGRPCListener(tlsConfig, addr)
	defer s.StopService()
	if err != nil {
		t.Fatal(err)
	}

	creds, err := tools.LoadTLSCredentials(sslClientCertFile, sslClientKeyFile, sslCertFile, true)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(creds)))
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := common.NewNodeServiceClient(conn)

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	baseCtx := context.Background()

	ctx, cancel := context.WithTimeout(baseCtx, 5*time.Second)
	defer cancel()

	_, err = client.GetBaseInfo(ctx, &common.Empty{})
	if err != nil {
		log.Println("info error: ", err)
	} else {
		t.Fatal("expected session ID error")
	}

	ctx, cancel = context.WithTimeout(baseCtx, 5*time.Second)
	defer cancel()

	info, err := client.Start(ctx,
		&common.Backend{
			Type:      common.BackendType_XRAY,
			Config:    string(configFile),
			KeepAlive: 10,
		})
	if err != nil {
		t.Fatal(err)
	}

	sessionID := info.SessionId
	log.Println("Session ID:", sessionID)

	// Add SessionId to the metadata
	md := metadata.Pairs("authorization", "Bearer "+info.SessionId)
	ctxWithSession := metadata.NewOutgoingContext(context.Background(), md)

	// test all methods
	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	// test GetBackendStats
	backStats, err := client.GetBackendStats(ctx, &common.Empty{})
	if err != nil {
		t.Fatalf("Failed to get backend stats: %v", err)
	}
	log.Println(backStats)

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	// test GetOutboundsStats
	stats, err := client.GetOutboundsStats(ctx, &common.StatRequest{Reset_: true})
	if err != nil {
		t.Fatalf("Failed to get outbounds stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	// test GetInboundsStats
	stats, err = client.GetInboundsStats(ctx, &common.StatRequest{Reset_: true})
	if err != nil {
		t.Fatalf("Failed to get inbounds stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	// test GetUsersStats
	stats, err = client.GetUsersStats(ctx, &common.StatRequest{Reset_: true})
	if err != nil {
		t.Fatalf("Failed to get users stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 10*time.Second)
	defer cancel()

	syncUser, _ := client.SyncUser(ctx)

	user := &common.User{
		Email: "test_user1@example.com",
		Inbounds: []string{
			"VMESS TCP NOTLS",
			"VLESS TCP REALITY",
			"TROJAN TCP NOTLS",
			"Shadowsocks TCP",
			"Shadowsocks UDP",
		},
		Proxies: &common.Proxy{
			Vmess: &common.Vmess{
				Id: uuid.New().String(),
			},
			Vless: &common.Vless{
				Id: uuid.New().String(),
			},
			Trojan: &common.Trojan{
				Password: "try a random string",
			},
			Shadowsocks: &common.Shadowsocks{
				Password: "try a random string",
				Method:   "aes-256-gcm",
			},
		},
	}

	if err = syncUser.Send(user); err != nil {
		t.Fatalf("Failed to sync user: %v", err)
	}

	user = &common.User{
		Email: "test_user2@example.com",
		Inbounds: []string{
			"VMESS TCP NOTLS",
			"VLESS TCP REALITY",
			"TROJAN TCP NOTLS",
			"Shadowsocks TCP",
			"Shadowsocks UDP",
		},
		Proxies: &common.Proxy{
			Vmess: &common.Vmess{
				Id: uuid.New().String(),
			},
			Vless: &common.Vless{
				Id: uuid.New().String(),
			},
			Trojan: &common.Trojan{
				Password: "try a random string",
			},
			Shadowsocks: &common.Shadowsocks{
				Password: "try a random string",
				Method:   "aes-256-gcm",
			},
		},
	}

	if err = syncUser.Send(user); err != nil {
		t.Fatalf("Failed to sync user: %v", err)
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	stats, err = client.GetUserStats(ctx, &common.StatRequest{Name: user.GetEmail(), Reset_: true})
	if err != nil {
		t.Fatalf("Failed to get user stats: %v", err)
	}
	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	stats, err = client.GetOutboundStats(ctx, &common.StatRequest{Name: "direct", Reset_: true})
	if err != nil {
		t.Fatalf("Failed to get outbound stats: %v", err)
	}
	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	stats, err = client.GetInboundStats(ctx, &common.StatRequest{Name: "Shadowsocks TCP", Reset_: true})
	if err != nil {
		t.Fatalf("Failed to get inbound stats: %v", err)
	}
	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	// test GetLogs Stream
	logs, _ := client.GetLogs(ctx, &common.Empty{})
loop:
	for {
		newLog, err := logs.Recv()
		if err == io.EOF {
			break loop
		}

		if errStatus, ok := status.FromError(err); ok {
			switch errStatus.Code() {
			case codes.DeadlineExceeded:
				log.Printf("Operation timed out: %v", err)
				break loop
			case codes.Canceled:
				log.Printf("Operation was canceled: %v", err)
				break loop
			default:
				if err != nil {
					t.Fatalf("Failed to receive log: %v (gRPC code: %v)", err, errStatus.Code())
				}
			}
		}

		if newLog != nil {
			fmt.Println("Log detail:", newLog.Detail)
		}
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	// test GetNodeStats
	nodeStats, err := client.GetSystemStats(ctx, &common.Empty{})
	if err != nil {
		t.Fatalf("Failed to get node stats: %v", err)
	}
	log.Println(nodeStats)

	// test keep alive
	time.Sleep(16 * time.Second)

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	_, err = client.GetBaseInfo(ctx, &common.Empty{})
	if err != nil {
		log.Println("info error: ", err)
	} else {
		t.Fatal("expected session ID error")
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	if err = shutdownFunc(ctx); err != nil {
		t.Fatalf("Failed to shutdown server: %v", err)
	}
}
