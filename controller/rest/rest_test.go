package rest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

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
	client                              *http.Client
	url                                 string
	shutdownFunc                        func(ctx context.Context) error
	service                             controller.Service
	createAuthenticatedRequest          func(method, endpoint string, data proto.Message, response proto.Message) error
	createAuthenticatedStreamingRequest func(method, endpoint string) (io.ReadCloser, error)
}

func TestMain(m *testing.M) {
	// Setup
	cfg := config.NewTestConfig(generatedConfigPath, apiKey)

	tlsConfig, err := tools.LoadTLSCredentials(sslCertFile, sslKeyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS credentials: %v", err)
	}

	shutdownFunc, s, err := StartHttpListener(tlsConfig, addr, cfg)
	if err != nil {
		log.Fatalf("Failed to start HTTP listener: %v", err)
	}

	certPool, err := tools.LoadClientPool(sslCertFile)
	if err != nil {
		log.Fatalf("Failed to load client pool: %v", err)
	}
	client := tools.CreateHTTPClient(certPool, nodeHost)

	url := fmt.Sprintf("https://%s", addr)

	createAuthenticatedRequest := func(method, endpoint string, data proto.Message, response proto.Message) error {
		body, err := proto.Marshal(data)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(method, url+endpoint, bytes.NewBuffer(body))
		if err != nil {
			return err
		}
		req.Header.Set("x-api-key", apiKey.String())
		if body != nil {
			req.Header.Set("Content-Type", "application/x-protobuf")
		}

		do, err := client.Do(req)
		if err != nil {
			return err
		}
		defer do.Body.Close()

		responseBody, _ := io.ReadAll(do.Body)
		if err = proto.Unmarshal(responseBody, response); err != nil {
			return err
		}
		return nil
	}

	createAuthenticatedStreamingRequest := func(method, endpoint string) (io.ReadCloser, error) {
		req, err := http.NewRequest(method, url+endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("x-api-key", apiKey.String())

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			defer resp.Body.Close()
			return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		return resp.Body, nil
	}

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

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

	backendStartReq := &common.Backend{
		Type:   common.BackendType_XRAY,
		Config: string(configFile),
		Users:  []*common.User{user1, user2},
	}

	var baseInfoResp common.BaseInfoResponse
	if err = createAuthenticatedRequest("POST", "/start", backendStartReq, &baseInfoResp); err != nil {
		log.Fatalf("Failed to start backend: %v", err)
	}

	sharedTestCtx = &testContext{
		client:                              client,
		url:                                 url,
		shutdownFunc:                        shutdownFunc,
		service:                             s,
		createAuthenticatedRequest:          createAuthenticatedRequest,
		createAuthenticatedStreamingRequest: createAuthenticatedStreamingRequest,
	}

	// Run tests
	code := m.Run()

	// Teardown
	s.Disconnect()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err = shutdownFunc(ctx); err != nil {
		log.Printf("Failed to shutdown server: %v", err)
	}

	os.Exit(code)
}

func TestREST_GetOutboundsStats(t *testing.T) {
	var stats common.StatResponse
	if err := sharedTestCtx.createAuthenticatedRequest("GET", "/stats", &common.StatRequest{Reset_: true, Type: common.StatType_Outbounds}, &stats); err != nil {
		t.Fatalf("Failed to get outbound stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Printf("Outbound Stat - Name: %s, Traffic: %d, Type: %s, Link: %s",
			stat.GetName(), stat.GetValue(), stat.GetType(), stat.GetLink())
	}
}

func TestREST_GetInboundsStats(t *testing.T) {
	var stats common.StatResponse
	if err := sharedTestCtx.createAuthenticatedRequest("GET", "/stats", &common.StatRequest{Reset_: true, Type: common.StatType_Inbounds}, &stats); err != nil {
		t.Fatalf("Failed to get inbounds stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Printf("Inbound Stat - Name: %s, Traffic: %d, Type: %s, Link: %s",
			stat.GetName(), stat.GetValue(), stat.GetType(), stat.GetLink())
	}
}

func TestREST_GetUsersStats(t *testing.T) {
	var stats common.StatResponse
	if err := sharedTestCtx.createAuthenticatedRequest("GET", "/stats", &common.StatRequest{Reset_: true, Type: common.StatType_UsersStat}, &stats); err != nil {
		t.Fatalf("Failed to get users stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Printf("Users Stat - Name: %s, Traffic: %d, Type: %s, Link: %s",
			stat.GetName(), stat.GetValue(), stat.GetType(), stat.GetLink())
	}
}

func TestREST_GetBackendStats(t *testing.T) {
	var backendStats common.BackendStatsResponse
	if err := sharedTestCtx.createAuthenticatedRequest("GET", "/stats/backend", &common.Empty{}, &backendStats); err != nil {
		t.Fatalf("Failed to get backend stats: %v", err)
	}
	fmt.Println(backendStats)
}

func TestREST_SyncUser(t *testing.T) {
	user := &common.User{
		Email: "test_user1@example.com",
		Inbounds: []string{
			"VMESS TCP NOTLS",
			"VLESS TCP REALITY",
		},
		Proxies: &common.Proxy{
			Vmess: &common.Vmess{
				Id: uuid.New().String(),
			},
		},
	}

	if err := sharedTestCtx.createAuthenticatedRequest("PUT", "/user/sync", user, &common.Empty{}); err != nil {
		t.Fatalf("Sync user request failed: %v", err)
	}
}

func TestREST_SyncUsersChunked(t *testing.T) {
	firstChunk := &common.UsersChunk{
		Index: 0,
		Users: []*common.User{
			{
				Email: "chunk_rest_user1@example.com",
				Inbounds: []string{
					"VMESS TCP NOTLS",
					"TROJAN TCP NOTLS",
				},
				Proxies: &common.Proxy{
					Vmess: &common.Vmess{
						Id: uuid.New().String(),
					},
					Trojan: &common.Trojan{
						Password: "try a random string",
					},
				},
			},
		},
	}

	secondChunk := &common.UsersChunk{
		Index: 1,
		Users: []*common.User{
			{
				Email: "chunk_rest_user2@example.com",
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

	var body bytes.Buffer
	appendChunk := func(chunk *common.UsersChunk) {
		data, err := proto.Marshal(chunk)
		if err != nil {
			t.Fatalf("failed to marshal chunk: %v", err)
		}

		var lenBuf [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(lenBuf[:], uint64(len(data)))
		body.Write(lenBuf[:n])
		body.Write(data)
	}

	appendChunk(firstChunk)
	appendChunk(secondChunk)

	req, err := http.NewRequest("PUT", sharedTestCtx.url+"/users/sync/chunked", bytes.NewReader(body.Bytes()))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("x-api-key", apiKey.String())
	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := sharedTestCtx.client.Do(req)
	if err != nil {
		t.Fatalf("failed to send chunked request: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var empty common.Empty
	if err = proto.Unmarshal(respBody, &empty); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
}

func TestREST_GetLogsStream(t *testing.T) {
	reader, err := sharedTestCtx.createAuthenticatedStreamingRequest("GET", "/logs")
	if err != nil {
		t.Fatalf("Failed to start streaming logs: %v", err)
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}

	if err = scanner.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			t.Logf("Skipping context deadline exceeded error: %v", err)
			return
		}
		t.Fatalf("Error reading streaming logs: %v", err)
	}
}

func TestREST_GetSystemStats(t *testing.T) {
	var systemStats common.SystemStatsResponse
	if err := sharedTestCtx.createAuthenticatedRequest("GET", "/stats/system", &common.Empty{}, &systemStats); err != nil {
		t.Fatalf("Node stats request failed: %v", err)
	}

	fmt.Printf("System Stats: \nMem Total: %d \nMem Used: %d \nCpu Number: %d \nCpu Usage: %f \nIncoming: %d \nOutgoing: %d \n",
		systemStats.MemTotal, systemStats.MemUsed, systemStats.CpuCores, systemStats.CpuUsage, systemStats.IncomingBandwidthSpeed, systemStats.OutgoingBandwidthSpeed)
}

func TestREST_StopBackend(t *testing.T) {
	user := &common.User{}
	if err := sharedTestCtx.createAuthenticatedRequest("PUT", "/stop", user, &common.Empty{}); err != nil {
		t.Fatalf("Stop backend request failed: %v", err)
	}
}
