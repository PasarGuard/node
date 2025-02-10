package rest

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/m03ed/marzban-node-go/common"
	"github.com/m03ed/marzban-node-go/config"
	nodeLogger "github.com/m03ed/marzban-node-go/logger"
	"github.com/m03ed/marzban-node-go/tools"
)

var (
	servicePort         = 8002
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

// httpClient creates a custom HTTP client with TLS configuration
func createHTTPClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 10 * time.Second,
	}
}

func TestRESTConnection(t *testing.T) {
	config.SetEnv(servicePort, 1000, nodeHost, xrayExecutablePath, xrayAssetsPath,
		sslCertFile, sslKeyFile, sslClientCertFile, "rest", generatedConfigPath, true)

	nodeLogger.SetOutputMode(true)

	certFileExists := tools.FileExists(sslCertFile)
	keyFileExists := tools.FileExists(sslKeyFile)
	if !certFileExists || !keyFileExists {
		if err := tools.RewriteSslFile(sslCertFile, sslKeyFile); err != nil {
			t.Fatal(err)
		}
	}

	clientFileExists := tools.FileExists(sslClientCertFile)
	if !clientFileExists {
		t.Fatal("SSL_CLIENT_CERT_FILE is required.")
	}

	tlsConfig, err := tools.LoadTLSCredentials(sslCertFile, sslKeyFile, sslClientCertFile, false)
	if err != nil {
		t.Fatal(err)
	}

	shutdownFunc, s, err := StartHttpListener(tlsConfig, addr)
	if err != nil {
		t.Fatalf("Failed to start HTTP listener: %v", err)
	}
	defer s.StopService()

	creds, err := tools.LoadTLSCredentials(sslClientCertFile, sslClientKeyFile, sslCertFile, true)
	if err != nil {
		t.Fatal(err)
	}

	url := fmt.Sprintf("https://%s", addr)

	client := createHTTPClient(creds)
	sessionId := ""

	createAuthenticatedRequest := func(method, endpoint string, data proto.Message, response proto.Message) error {
		body, err := proto.Marshal(data)
		if err != nil {
			return err
		}

		req, err := http.NewRequest(method, url+endpoint, bytes.NewBuffer(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+sessionId)
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

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

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
		Users:  []*common.User{user, user2},
	}

	var baseInfoResp common.BaseInfoResponse
	if err = createAuthenticatedRequest("POST", "/start", backendStartReq, &baseInfoResp); err != nil {
		t.Fatalf("Failed to start backend: %v", err)
	}

	sessionId = baseInfoResp.GetSessionId()
	if sessionId == "" {
		t.Fatal("No session ID received")
	}

	var stats common.StatResponse
	// Try To Get Outbounds Stats
	if err = createAuthenticatedRequest("GET", "/stats/outbounds", &common.StatRequest{Reset_: true}, &stats); err != nil {
		t.Fatalf("Failed to get outbound stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Printf("Outbound Stat - Name: %s, Traffic: %d, Type: %s, Link: %s",
			stat.GetName(), stat.GetValue(), stat.GetType(), stat.GetLink())
	}

	if err = createAuthenticatedRequest("GET", "/stats/inbounds", &common.StatRequest{Reset_: true}, &stats); err != nil {
		t.Fatalf("Failed to get inbounds stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Printf("Inbound Stat - Name: %s, Traffic: %d, Type: %s, Link: %s",
			stat.GetName(), stat.GetValue(), stat.GetType(), stat.GetLink())
	}

	if err = createAuthenticatedRequest("GET", "/stats/users", &common.StatRequest{Reset_: true}, &stats); err != nil {
		t.Fatalf("Failed to get users stats: %v", err)
	}

	for _, stat := range stats.GetStats() {
		log.Printf("Users Stat - Name: %s, Traffic: %d, Type: %s, Link: %s",
			stat.GetName(), stat.GetValue(), stat.GetType(), stat.GetLink())
	}

	var backendStats common.BackendStatsResponse
	if err = createAuthenticatedRequest("GET", "/stats/backend", &common.Empty{}, &backendStats); err != nil {
		t.Fatalf("Failed to get backend stats: %v", err)
	}

	fmt.Println(backendStats)

	if err = createAuthenticatedRequest("PUT", "/user/sync", user, &common.Empty{}); err != nil {
		t.Fatalf("Sync user request failed: %v", err)
	}

	var logs common.LogList
	if err = createAuthenticatedRequest("GET", "/logs", &common.Empty{}, &logs); err != nil {
		t.Fatalf("Sync user request failed: %v", err)
	}

	for _, newLog := range logs.GetLogs() {
		fmt.Println("Log detail:", newLog)
	}

	// Try To Get Node Stats
	var systemStats common.SystemStatsResponse
	if err = createAuthenticatedRequest("GET", "/stats/system", &common.Empty{}, &systemStats); err != nil {
		t.Fatalf("Node stats request failed: %v", err)
	}

	fmt.Printf("System Stats: \nMem Total: %d \nMem Used: %d \nCpu Number: %d \nCpu Usage: %f \nIncoming: %d \nOutgoing: %d \n",
		systemStats.MemTotal, systemStats.MemUsed, systemStats.CpuCores, systemStats.CpuUsage, systemStats.IncomingBandwidthSpeed, systemStats.OutgoingBandwidthSpeed)

	if err = createAuthenticatedRequest("PUT", "/stop", user, &common.Empty{}); err != nil {
		t.Fatalf("Sync user request failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = shutdownFunc(ctx); err != nil {
		t.Fatalf("Failed to shutdown server: %v", err)
	}
}
