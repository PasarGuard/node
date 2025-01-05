package xray

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/m03ed/marzban-node-go/backend"
	"github.com/m03ed/marzban-node-go/common"
	"github.com/m03ed/marzban-node-go/tools"
)

var (
	jsonFile       = "./config.json"
	executablePath = "/usr/local/bin/xray"
	assetsPath     = "/usr/local/share/xray"
	configPath     = "../../generated/"
)

func TestXrayBackend(t *testing.T) {
	xrayFile, err := tools.ReadFileAsString(jsonFile)
	if err != nil {
		t.Fatal(err)
	}

	//test creating config
	newConfig, err := NewXRayConfig(xrayFile)
	if err != nil {
		t.Fatal(err)
	}

	log.Println("xray config created")

	// test HandlerServiceClient
	user := &common.User{
		Email: "test_user@example.com",
		Inbounds: []string{
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

	ctx := context.WithValue(context.Background(), backend.ConfigKey{}, newConfig)
	ctx = context.WithValue(ctx, backend.UsersKey{}, []*common.User{user, user2})

	back, err := NewXray(ctx, tools.FindFreePort(), executablePath, assetsPath, configPath)
	if err != nil {
		t.Fatal(err)
	}

	log.Println("xray started")

	ctx1, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// test with service StatsServiceClient
	stats, err := back.GetOutboundsStats(ctx1, true)
	if err != nil {
		t.Error(err)
	}

	for _, stat := range stats.Stats {
		log.Printf(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	if err = back.UpdateUser(ctx1, user); err != nil {
		t.Fatal(err)
	}

	log.Println("user added")

	if err = back.UpdateUser(ctx1, user2); err != nil {
		t.Fatal(err)
	}

	log.Println("user updated")

	ctx1, cancel = context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	logs := back.GetLogs()
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
