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

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller"
	"github.com/pasarguard/node/tools"
)

var (
	servicePort         = 8002
	nodeHost            = "127.0.0.1"
	sslCertFile         = "../../certs/ssl_cert.pem"
	sslKeyFile          = "../../certs/ssl_key.pem"
	apiKey              = uuid.New()
	generatedConfigPath = "../../generated/"
	addr                = fmt.Sprintf("%s:%d", nodeHost, servicePort)
	configPath          = "../../backend/xray/config.json"

	// Shared test context
	sharedTestCtx *testContext
)

type testContext struct {
	client         common.NodeServiceClient
	ctxWithSession context.Context
	shutdownFunc   func(ctx context.Context) error
	service        controller.Service
	conn           *grpc.ClientConn
}

func TestMain(m *testing.M) {
	// Setup
	cfg := config.NewTestConfig(generatedConfigPath, apiKey)

	tlsConfig, err := tools.LoadTLSCredentials(sslCertFile, sslKeyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS credentials: %v", err)
	}

	shutdownFunc, s, err := StartGRPCListener(tlsConfig, addr, cfg)
	if err != nil {
		log.Fatalf("Failed to start gRPC listener: %v", err)
	}

	certPool, err := tools.LoadClientPool(sslCertFile)
	if err != nil {
		log.Fatalf("Failed to load client pool: %v", err)
	}

	creds := credentials.NewClientTLSFromCert(certPool, "")
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server: %v", err)
	}

	client := common.NewNodeServiceClient(conn)
	md := metadata.Pairs("x-api-key", apiKey.String())
	ctxWithSession := metadata.NewOutgoingContext(context.Background(), md)

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	ctx, cancel := context.WithTimeout(ctxWithSession, 5*time.Second)
	_, err = client.Start(ctx, &common.Backend{
		Type:      common.BackendType_XRAY,
		Config:    string(configFile),
		KeepAlive: 10,
	})
	cancel()
	if err != nil {
		log.Fatalf("Failed to start backend: %v", err)
	}

	sharedTestCtx = &testContext{
		client:         client,
		ctxWithSession: ctxWithSession,
		shutdownFunc:   shutdownFunc,
		service:        s,
		conn:           conn,
	}

	// Run tests
	code := m.Run()

	// Teardown
	conn.Close()
	s.Disconnect()

	ctx, cancel = context.WithTimeout(ctxWithSession, 5*time.Second)
	defer cancel()

	if err := shutdownFunc(ctx); err != nil {
		log.Printf("Failed to shutdown server: %v", err)
	}

	os.Exit(code)
}

func TestGRPC_GetBackendStats(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 5*time.Second)
	defer cancel()

	backStats, err := sharedTestCtx.client.GetBackendStats(ctx, &common.Empty{})
	if err != nil {
		t.Fatalf("Failed to get backend stats: %v", err)
	}
	log.Println(backStats)
}

func TestGRPC_GetOutboundsStats(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 5*time.Second)
	defer cancel()

	stats, err := sharedTestCtx.client.GetStats(ctx, &common.StatRequest{Reset_: true, Type: common.StatType_Outbounds})
	if err != nil {
		t.Fatalf("Failed to get outbounds stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}
}

func TestGRPC_GetInboundsStats(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 5*time.Second)
	defer cancel()

	stats, err := sharedTestCtx.client.GetStats(ctx, &common.StatRequest{Reset_: true, Type: common.StatType_Inbounds})
	if err != nil {
		t.Fatalf("Failed to get inbounds stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}
}

func TestGRPC_GetUsersStats(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 5*time.Second)
	defer cancel()

	stats, err := sharedTestCtx.client.GetStats(ctx, &common.StatRequest{Reset_: true, Type: common.StatType_UsersStat})
	if err != nil {
		t.Fatalf("Failed to get users stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}
}

func TestGRPC_GetUserOnlineStats_NotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 5*time.Second)
	defer cancel()

	_, err := sharedTestCtx.client.GetUserOnlineStats(ctx, &common.StatRequest{Name: "does-not-exist@example.com"})
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Fatalf("Expected NotFound error, got: %v", err)
	}
}

func TestGRPC_GetUserOnlineIpListStats_NotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 5*time.Second)
	defer cancel()

	_, err := sharedTestCtx.client.GetUserOnlineIpListStats(ctx, &common.StatRequest{Name: "does-not-exist@example.com"})
	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Fatalf("Expected NotFound error, got: %v", err)
	}
}

func TestGRPC_SyncUsers(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 10*time.Second)
	defer cancel()

	syncUser, _ := sharedTestCtx.client.SyncUser(ctx)

	user1 := &common.User{
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

	if err := syncUser.Send(user1); err != nil {
		t.Fatalf("Failed to sync user1: %v", err)
	}

	user2 := &common.User{
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

	if err := syncUser.Send(user2); err != nil {
		t.Fatalf("Failed to sync user2: %v", err)
	}
}

func TestGRPC_SyncUsersChunked(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 10*time.Second)
	defer cancel()

	stream, err := sharedTestCtx.client.SyncUsersChunked(ctx)
	if err != nil {
		t.Fatalf("Failed to open chunked sync stream: %v", err)
	}

	firstChunk := &common.UsersChunk{
		Index: 0,
		Users: []*common.User{
			{
				Email: "chunk_user1@example.com",
				Inbounds: []string{
					"VMESS TCP NOTLS",
					"VLESS TCP REALITY",
				},
				Proxies: &common.Proxy{
					Vmess: &common.Vmess{
						Id: uuid.New().String(),
					},
					Vless: &common.Vless{
						Id: uuid.New().String(),
					},
				},
			},
		},
	}

	secondChunk := &common.UsersChunk{
		Index: 1,
		Users: []*common.User{
			{
				Email: "chunk_user2@example.com",
				Inbounds: []string{
					"Shadowsocks TCP",
					"Shadowsocks UDP",
				},
				Proxies: &common.Proxy{
					Shadowsocks: &common.Shadowsocks{
						Password: "try a random string",
						Method:   "aes-256-gcm",
					},
				},
			},
		},
		Last: true,
	}

	if err = stream.Send(firstChunk); err != nil {
		t.Fatalf("Failed to send first chunk: %v", err)
	}

	if err = stream.Send(secondChunk); err != nil {
		t.Fatalf("Failed to send final chunk: %v", err)
	}

	if _, err = stream.CloseAndRecv(); err != nil {
		t.Fatalf("Failed to complete chunked sync: %v", err)
	}
}

func TestGRPC_GetSpecificUserStats(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 5*time.Second)
	defer cancel()

	stats, err := sharedTestCtx.client.GetStats(ctx, &common.StatRequest{Name: "test_user2@example.com", Reset_: true, Type: common.StatType_UsersStat})
	if err != nil {
		t.Fatalf("Failed to get user stats: %v", err)
	}
	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}
}

func TestGRPC_GetSpecificOutboundStats(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 5*time.Second)
	defer cancel()

	stats, err := sharedTestCtx.client.GetStats(ctx, &common.StatRequest{Name: "direct", Reset_: true, Type: common.StatType_Outbound})
	if err != nil {
		t.Fatalf("Failed to get outbound stats: %v", err)
	}
	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}
}

func TestGRPC_GetSpecificInboundStats(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 5*time.Second)
	defer cancel()

	stats, err := sharedTestCtx.client.GetStats(ctx, &common.StatRequest{Name: "Shadowsocks TCP", Reset_: true, Type: common.StatType_Inbounds})
	if err != nil {
		t.Fatalf("Failed to get inbound stats: %v", err)
	}
	for _, stat := range stats.GetStats() {
		log.Println(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}
}

func TestGRPC_GetLogsStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 5*time.Second)
	defer cancel()

	logs, _ := sharedTestCtx.client.GetLogs(ctx, &common.Empty{})
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
}

func TestGRPC_GetSystemStats(t *testing.T) {
	ctx, cancel := context.WithTimeout(sharedTestCtx.ctxWithSession, 5*time.Second)
	defer cancel()

	nodeStats, err := sharedTestCtx.client.GetSystemStats(ctx, &common.Empty{})
	if err != nil {
		t.Fatalf("Failed to get node stats: %v", err)
	}
	log.Println("mem_total:", nodeStats.GetMemTotal())
	log.Println("mem_usage:", nodeStats.GetMemUsed())
	log.Println("cpu_usage:", nodeStats.GetCpuUsage())
	log.Println("cpu_cores:", nodeStats.GetCpuCores())
	log.Println("incoming_bandwidth:", nodeStats.GetIncomingBandwidthSpeed())
	log.Println("outgoing_bandwidth:", nodeStats.GetOutgoingBandwidthSpeed())
}

func TestGRPC_KeepAliveTimeout(t *testing.T) {
	// Wait for keep alive to timeout (10 seconds + buffer)
	time.Sleep(16 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := sharedTestCtx.client.GetBaseInfo(ctx, &common.Empty{})
	if err != nil {
		log.Println("info error: ", err)
	} else {
		t.Fatal("expected session ID error")
	}
}
