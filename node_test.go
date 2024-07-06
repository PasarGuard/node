package main

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	log "marzban-node/logger"
	"marzban-node/service"
	"marzban-node/tools"
	"marzban-node/xray"
	"regexp"
	"strings"
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

	err = newConfig.ApplyAPI(s.GetAPIPort())
	if err != nil {
		t.Error(err)
	}

	core := s.GetCore()

	log.Info("core created.")
	log.Info("Version: ", core.GetVersion())

	err = core.Start(newConfig)
	if err != nil {
		t.Error(err)
	}

	logChan := core.GetLogs()
	version := core.GetVersion()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

Loop:
	for {
		select {
		case lastLog := <-logChan:
			if strings.Contains(lastLog, "Xray "+version+" started") {
				break Loop
			} else {
				regex := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[([^\]]+)\] (.+)$`)
				matches := regex.FindStringSubmatch(lastLog)
				if len(matches) > 3 && matches[2] == "Error" {
					t.Error(matches)
				}
			}
		case <-ctx.Done():
			t.Error("context done")
			return
		}
	}

	if !core.Started() {
		t.Error("core is not running")
	}

	api := s.GetXrayAPI()
	log.Info("api created.")

	ctx1, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// test with service StatsServiceClient
	stats, err := api.GetOutboundsStats(ctx1, true)
	if err != nil {
		t.Error(err)
	}

	for _, stat := range stats {
		log.Info(fmt.Sprintf("Name: %s , Traffic: %d , Type: %s , Link: %s", stat.Name, stat.Value, stat.Type, stat.Link))
	}

	time.Sleep(10 * time.Second)
	// test HandlerServiceClient
	user := &xray.User{
		Email: "Mosed.1",
		Inbounds: &xray.Inbounds{
			Vmess:       []string{"VMESS_TCP_INBOUND", "VMESS_no_tls"},
			Vless:       []string{"VLESS_Reality"},
			Trojan:      []string{},
			Shadowsocks: []string{},
		},
		Proxies: &xray.Proxy{
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
	proxySetting := xray.SetupUserAccount(user)

	for _, inbound := range newConfig.Inbounds {
		account, isActive := xray.IsActiveInbound(inbound, user, proxySetting)
		if isActive {
			err = api.AddInboundUser(ctx2, inbound.Tag, account)
			if err != nil {
				t.Error(err)
			} else {
				log.Info("Added user to inbound ", inbound.Tag)
			}
		}
	}

	time.Sleep(time.Second * 10)

	core.Stop()
}
