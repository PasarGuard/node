package rpc

import (
	"context"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/m03ed/marzban-node-go/common"
	"github.com/m03ed/marzban-node-go/config"
	nodeLogger "github.com/m03ed/marzban-node-go/logger"
	"github.com/m03ed/marzban-node-go/tools"
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
	generatedConfigPath = "/var/lib/marzban-node/generated/"
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
			Type:   common.BackendType_XRAY,
			Config: string(configFile),
		})
	if err != nil {
		t.Fatal(err)
	}

	sessionID := info.SessionId
	log.Println("Session ID:", sessionID)

	// Add SessionId to the metadata
	md := metadata.Pairs("authorization", "Bearer "+sessionID)
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
	outboundStats, err := client.GetOutboundsStats(ctx, &common.Empty{})
	if err != nil {
		t.Fatalf("Failed to get outbounds stats: %v", err)
	}

	for _, stat := range outboundStats.Stats {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	// test GetInboundsStats
	inboundStats, err := client.GetInboundsStats(ctx, &common.Empty{})
	if err != nil {
		t.Fatalf("Failed to get inbounds stats: %v", err)
	}

	for _, stat := range inboundStats.Stats {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	// test GetUsersStats
	usersStats, err := client.GetUsersStats(ctx, &common.Empty{})
	if err != nil {
		t.Fatalf("Failed to get users stats: %v", err)
	}

	for _, stat := range usersStats.Stats {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	user := &common.User{
		Email:    "test_user1@example.com",
		Inbounds: []string{"VMESS TCP NOTLS", "VLESS TCP REALITY", "TROJAN TCP NOTLS", "Shadowsocks TCP", "Shadowsocks UDP"},
		Proxies: &common.Proxy{
			Vmess: &common.VmessSetting{
				Id: uuid.New().String(),
			},
			Vless: &common.VlessSetting{
				Id: uuid.New().String(),
			},
			Trojan: &common.TrojanSetting{
				Password: "try a random string",
			},
			Shadowsocks: &common.ShadowsocksSetting{
				Password: "try a random string",
				Method:   "AES_256_GCM",
			},
		},
	}

	// test AddUser
	if _, err = client.AddUser(ctx, user); err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	user = &common.User{
		Email:    "test_user2@example.com",
		Inbounds: []string{"VMESS TCP NOTLS", "VLESS TCP REALITY", "TROJAN TCP NOTLS", "Shadowsocks TCP", "Shadowsocks UDP"},
		Proxies: &common.Proxy{
			Vmess: &common.VmessSetting{
				Id: uuid.New().String(),
			},
			Vless: &common.VlessSetting{
				Id: uuid.New().String(),
			},
			Trojan: &common.TrojanSetting{
				Password: "try a random string",
			},
			Shadowsocks: &common.ShadowsocksSetting{
				Password: "try a random string",
				Method:   "AES_128_GCM",
			},
		},
	}

	// test UpdateUser
	if _, err = client.UpdateUser(ctx, user); err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	// test RemoveUser
	if _, err = client.RemoveUser(ctx, user); err != nil {
		t.Fatalf("Failed to remove user: %v", err)
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
	nodeStats, err := client.GetNodeStats(ctx, &common.Empty{})
	if err != nil {
		t.Fatalf("Failed to get node stats: %v", err)
	}
	log.Println(nodeStats)

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	if _, err = client.Stop(ctx, nil); err != nil {
		t.Fatalf("Failed to stop s: %v", err)
	}

	if err = shutdownFunc(ctx); err != nil {
		t.Fatalf("Failed to shutdown server: %v", err)
	}
}
