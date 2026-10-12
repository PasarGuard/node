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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/controller"
	"github.com/pasarguard/node/pkg/tlsutil"
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

	tlsConfig, err := tlsutil.LoadTLSCredentials(sslCertFile, sslKeyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS credentials: %v", err)
	}

	shutdownFunc, s, err := StartHttpListener(tlsConfig, addr, cfg)
	if err != nil {
		log.Fatalf("Failed to start HTTP listener: %v", err)
	}

	certPool, err := tlsutil.LoadClientPool(sslCertFile)
	if err != nil {
		log.Fatalf("Failed to load client pool: %v", err)
	}
	client := tlsutil.CreateHTTPClient(certPool, nodeHost)

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
	fmt.Println(backendStats.String())
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

func TestREST_Routing(t *testing.T) {
	doRouting := func(method, endpoint string, reqMsg proto.Message) (int, []byte) {
		var body []byte
		if reqMsg != nil {
			var err error
			if body, err = proto.Marshal(reqMsg); err != nil {
				t.Fatalf("marshal request: %v", err)
			}
		}
		req, err := http.NewRequest(method, sharedTestCtx.url+endpoint, bytes.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("x-api-key", apiKey.String())
		req.Header.Set("Content-Type", "application/x-protobuf")
		resp, err := sharedTestCtx.client.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, respBody
	}

	// assertRegistered confirms a route exists (handler ran) rather than chi's
	// default not-found, regardless of whether the routing op itself succeeds.
	assertRegistered := func(method, endpoint string, reqMsg proto.Message) {
		code, body := doRouting(method, endpoint, reqMsg)
		if code == http.StatusNotFound && strings.Contains(string(body), "404 page not found") {
			t.Fatalf("%s %s not registered (chi 404)", method, endpoint)
		}
	}

	// List rules (RoutingService enabled in the test config) -> 200 + decodes.
	code, body := doRouting("GET", "/routing/rules", &common.Empty{})
	if code != http.StatusOK {
		t.Fatalf("ListRoutingRules: status = %d, body = %s", code, body)
	}
	var rules common.RoutingRulesResponse
	if err := proto.Unmarshal(body, &rules); err != nil {
		t.Fatalf("decode RoutingRulesResponse: %v", err)
	}

	// Two adds with the default (should_reset unset) must APPEND: the second add
	// must keep the first rule rather than resetting the router. This guards the
	// safe, non-destructive wire default.
	addTags := []string{"rest-routing-test-a", "rest-routing-test-b"}
	for _, tag := range addTags {
		code, body = doRouting("PUT", "/routing/rules", &common.AddRoutingRuleRequest{
			Rule: `{"type":"field","outboundTag":"direct","domain":["` + tag + `.example.com"],"ruleTag":"` + tag + `"}`,
		})
		if code != http.StatusOK {
			t.Fatalf("AddRoutingRule(%s): status = %d, body = %s", tag, code, body)
		}
	}
	code, body = doRouting("GET", "/routing/rules", &common.Empty{})
	if code != http.StatusOK {
		t.Fatalf("ListRoutingRules(after appends): status = %d, body = %s", code, body)
	}
	var listed common.RoutingRulesResponse
	if err := proto.Unmarshal(body, &listed); err != nil {
		t.Fatalf("decode RoutingRulesResponse: %v", err)
	}
	tags := make(map[string]bool)
	for _, ru := range listed.GetRules() {
		tags[ru.GetRuleTag()] = true
	}
	if !tags["rest-routing-test-a"] || !tags["rest-routing-test-b"] {
		t.Fatalf("default add did not append (both rules should survive); got tags = %v", tags)
	}
	for _, tag := range addTags {
		if code, body = doRouting("DELETE", "/routing/rules", &common.RemoveRoutingRuleRequest{RuleTag: tag}); code != http.StatusOK {
			t.Fatalf("RemoveRoutingRule(%s): status = %d, body = %s", tag, code, body)
		}
	}

	// Malformed rule JSON -> 400 (InvalidArgument mapped to HTTP).
	code, body = doRouting("PUT", "/routing/rules", &common.AddRoutingRuleRequest{Rule: "{not json"})
	if code != http.StatusBadRequest {
		t.Fatalf("AddRoutingRule(malformed): status = %d, want 400, body = %s", code, body)
	}

	// Remaining routes: confirm they are wired (handler runs, not chi 404).
	// Balancer info and test-route are POST because they carry request bodies.
	assertRegistered("POST", "/routing/balancer", &common.BalancerInfoRequest{Tag: "none"})
	assertRegistered("POST", "/routing/test", &common.TestRouteRequest{Network: "tcp", TargetDomain: "example.com"})
	assertRegistered("PUT", "/routing/balancer/override", &common.OverrideBalancerTargetRequest{BalancerTag: "none", Target: "none"})
}

func TestREST_StopBackend(t *testing.T) {
	user := &common.User{}
	if err := sharedTestCtx.createAuthenticatedRequest("PUT", "/stop", user, &common.Empty{}); err != nil {
		t.Fatalf("Stop backend request failed: %v", err)
	}
}
