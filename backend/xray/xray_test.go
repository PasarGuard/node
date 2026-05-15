package xray

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/pasarguard/node/common"
	"github.com/pasarguard/node/config"
	"github.com/pasarguard/node/pkg/fsutil"
	"github.com/pasarguard/node/pkg/netutil"
)

var (
	jsonFile       = "./config.json"
	executablePath = "/usr/local/bin/xray"
	assetsPath     = "/usr/local/share/xray"
	configPath     = "../../generated/"
)

func TestXrayBackend(t *testing.T) {
	xrayFile, err := fsutil.ReadFileAsString(jsonFile)
	if err != nil {
		t.Fatal(err)
	}

	//test creating config
	newConfig, err := NewConfig(xrayFile, nil)
	if err != nil {
		t.Fatal(err)
	}

	log.Println("xray config created")

	// test HandlerServiceClient
	user := &common.User{
		Email: "test_user@example.com",
		Inbounds: []string{
			"Shadowsocks 2022",
			"VMESS TCP NOTLS",
			"VLESS TCP REALITY",
			"TROJAN TCP NOTLS",
			"Shadowsocks TCP",
			"Shadowsocks UDP",
			"VLESS TCP Header NoTLS",
		},
		Proxies: &common.Proxy{
			Vmess: &common.Vmess{
				Id: uuid.New().String(),
			},
			Vless: &common.Vless{
				Id:   uuid.New().String(),
				Flow: "xtls-rprx-vision",
			},
			Trojan: &common.Trojan{
				Password: "try a random string",
			},
			Shadowsocks: &common.Shadowsocks{
				Password: "try a random string",
				Method:   "aes-128-gcm",
			},
		},
	}

	user2 := &common.User{
		Email: "test_user1@example.com",
		Inbounds: []string{
			"VLESS TCP REALITY",
			"VLESS TCP NOTLS",
			"Shadowsocks TCP",
			"Shadowsocks UDP",
		},
		Proxies: &common.Proxy{
			Vmess: &common.Vmess{
				Id: uuid.New().String(),
			},
			Vless: &common.Vless{
				Id:   uuid.New().String(),
				Flow: "xtls-rprx-vision",
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

	cfg := &config.Config{
		XrayExecutablePath:  executablePath,
		XrayAssetsPath:      assetsPath,
		GeneratedConfigPath: configPath,
		Debug:               false,
		LogBufferSize:       1000,
	}

	back, err := New(
		context.Background(),
		newConfig,
		[]*common.User{user, user2},
		netutil.FindFreePort(),
		netutil.FindFreePort(),
		cfg,
	)
	if err != nil {
		t.Fatal(err)
	}

	log.Println("xray started")

	ctx1, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// test with service StatsServiceClient
	stats, err := back.handler.GetOutboundsStats(ctx1, true)
	if err != nil {
		t.Error(err)
	}

	for _, stat := range stats.GetStats() {
		log.Printf("Name: %s , Traffic: %d , Type: %s , Link: %s",
			stat.GetName(), stat.GetValue(), stat.GetType(), stat.GetLink())
	}

	if err = back.SyncUser(ctx1, user2); err != nil {
		t.Fatal(err)
	}

	log.Println("user synced")

	ctx1, cancel = context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	logs := back.Logs()
loop:
	for {
		select {
		case newLog, ok := <-logs:
			if !ok {
				log.Println("channel closed")
				break loop
			}
			fmt.Println(newLog)
		case <-ctx1.Done():
			break loop
		}
	}

	back.Shutdown()
}

func TestGetOutboundsLatencyWithRealXray(t *testing.T) {
	xrayFile, err := fsutil.ReadFileAsString(jsonFile)
	if err != nil {
		t.Fatal(err)
	}

	newConfig, err := NewConfig(xrayFile, nil)
	if err != nil {
		t.Fatal(err)
	}

	newConfig.Observatory = map[string]any{
		"subjectSelector":   []string{"direct"},
		"probeUrl":          "https://www.google.com/generate_204",
		"probeInterval":     "1s",
		"enableConcurrency": true,
	}

	cfg := &config.Config{
		XrayExecutablePath:  executablePath,
		XrayAssetsPath:      assetsPath,
		GeneratedConfigPath: configPath,
		Debug:               false,
		LogBufferSize:       1000,
	}

	back, err := New(
		context.Background(),
		newConfig,
		nil,
		netutil.FindFreePort(),
		netutil.FindFreePort(),
		cfg,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer back.Shutdown()

	var resp *common.LatencyResponse
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		resp, err = back.GetOutboundsLatency(ctx, &common.LatencyRequest{Name: "direct"})
		if err == nil && len(resp.GetLatencies()) > 0 {
			break
		}

		select {
		case <-ctx.Done():
			if err != nil {
				t.Fatalf("timed out waiting for observatory data: %v", err)
			}
			t.Fatal("timed out waiting for observatory data")
		case <-ticker.C:
		}
	}

	latency := resp.GetLatencies()[0]
	if latency.GetName() != "direct" {
		t.Fatalf("unexpected name: got %s want direct", latency.GetName())
	}
	if latency.GetSource() != "xray-observatory" {
		t.Fatalf("unexpected source: got %s want xray-observatory", latency.GetSource())
	}
	if latency.GetLastTryTime() == 0 {
		t.Fatal("expected last_try_time to be populated")
	}
}

func TestLoopbackListenAddressUsesProvidedPort(t *testing.T) {
	if got := loopbackListenAddress(11111); got != "127.0.0.1:11111" {
		t.Fatalf("unexpected listen address: got %s", got)
	}
}
