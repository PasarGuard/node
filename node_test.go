package main

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	log "marzban-node/logger"
	"marzban-node/service"
	"marzban-node/tools"
	"marzban-node/xray"
	"testing"
	"time"
)

func TestService(t *testing.T) {
	xrayFile, err := tools.ReadFileAsString("xray.json")
	if err != nil {
		t.Error(err)
	}

	//test creating config
	newConfig, err := xray.NewXRayConfig(xrayFile)
	if err != nil {
		t.Error(err)
	}

	s := new(service.Service)
	err = s.Init()
	if err != nil {
		t.Error(err)
	}

	core := s.GetCore()

	log.InfoLog("core created.")
	log.InfoLog("Version: ", core.Version)

	err = newConfig.ApplyAPI(s.GetAPIPort())
	if err != nil {
		t.Error(err)
	}

	err = core.Start(*newConfig)
	if err != nil {
		t.Error(err)
	}
	time.Sleep(20 * time.Second)

	api := s.GetXrayAPI()

	ctx1, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// test with service StatsServiceClient
	stats, err := api.GetOutboundsStats(ctx1, true)
	if err != nil {
		t.Error(err)
	}
	for _, stat := range stats {
		log.InfoLog(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	// test HandlerServiceClient
	user := xray.User{
		ID:       1,
		Username: "Mosed",
		Inbounds: xray.Inbounds{
			Vmess:       []string{"VMESS_TCP_INBOUND", "VMESS_no_tls"},
			Vless:       []string{"VLESS_Reality"},
			Trojan:      []string{},
			Shadowsocks: []string{},
		},
		Proxies: xray.Proxy{
			Vmess: &xray.VmessSetting{
				ID: uuid.New(),
			},
			Vless: &xray.VlessSetting{
				ID: uuid.New(),
			},
		},
	}

	ctx2, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	email := fmt.Sprintf("%s.%d", user.Username, user.ID)
	proxySetting := xray.SetupUserAccount(user, email)

	for _, inbound := range newConfig.Inbounds {
		account, isActive := xray.IsActiveInbound(inbound, user, proxySetting)
		if isActive {
			err = api.AddInboundUser(ctx2, inbound.Tag, account)
			if err != nil {
				t.Error(err)
			} else {
				log.InfoLog("Added user to inbound ", inbound.Tag)
			}
		}
	}
}
