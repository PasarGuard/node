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

	ctx := context.WithValue(context.Background(), backend.ConfigKey{}, newConfig)

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

	// test HandlerServiceClient
	user := &common.User{
		Email: "test_user@example.com",
		Inbounds: []string{
			"VMESS TCP NOTLS",
			"VLESS TCP REALITY",
			"TROJAN TCP NOTLS",
			"Shadowsocks TCP",
			"Shadowsocks UDP",
		},
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

	if err = back.AddUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	log.Println("user added")

	user = &common.User{
		Email: "test_user@example.com",
		Inbounds: []string{
			"VLESS TCP REALITY",
			"Shadowsocks TCP",
			"Shadowsocks UDP",
		},
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

	if err = back.RemoveUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	log.Println("user updated")

	back.Shutdown()
}
