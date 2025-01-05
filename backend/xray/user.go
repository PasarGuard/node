package xray

import (
	"context"
	"errors"
	"log"
	"slices"
	"strings"

	"github.com/m03ed/marzban-node-go/backend/xray/api"
	"github.com/m03ed/marzban-node-go/common"
)

func setupUserAccount(user *common.User) (api.ProxySettings, error) {
	settings := api.ProxySettings{}

	vmessAccount, err := api.NewVMessAccount(user)
	if err != nil {
		return settings, err
	}
	settings.Vmess = vmessAccount

	vlessAccount, err := api.NewVlessAccount(user)
	if err != nil {
		return settings, err
	}
	settings.Vless = vlessAccount

	settings.Trojan = api.NewTrojanAccount(user)

	settings.Shadowsocks = api.NewShadowsocksTcpAccount(user)

	settings.Shadowsocks2022 = api.NewShadowsocksAccount(user)

	return settings, nil
}

func isActiveInbound(inbound *Inbound, inbounds []string, settings api.ProxySettings) (api.Account, bool) {
	if slices.Contains(inbounds, inbound.Tag) {
		switch inbound.Protocol {
		case Vless:
			account := *settings.Vless
			if settings.Vless.Flow != "" {
				networkType := inbound.StreamSettings["network"]

				if !(networkType == "tcp" || networkType == "mkcp") {
					account.Flow = ""
					return &account, true
				}

				securityType := inbound.StreamSettings["security"]

				if !(securityType == "tls" || securityType == "reality") {
					account.Flow = ""
					return &account, true
				}

				rawMap, ok := inbound.StreamSettings["rawSettings"].(map[string]interface{})
				if !ok {
					rawMap, ok = inbound.StreamSettings["tcpSettings"].(map[string]interface{})
					if !ok {
						return &account, true
					}
				}

				headerMap, ok := rawMap["header"].(map[string]interface{})
				if !ok {
					return &account, true
				}

				headerType, ok := headerMap["Type"].(string)
				if !ok {
					return &account, true
				}

				if headerType == "http" {
					account.Flow = ""
					return &account, true
				}
			}
			return &account, true

		case Vmess:
			return settings.Vmess, true

		case Trojan:
			return settings.Trojan, true

		case Shadowsocks:
			method, methodOk := inbound.Settings["method"].(string)
			if methodOk && strings.HasPrefix("2022-blake3", method) {
				return settings.Shadowsocks2022, true
			}
			return settings.Shadowsocks, true
		}
	}
	return nil, false
}

func (x *Xray) AddUser(ctx context.Context, user *common.User) error {
	proxySetting, err := setupUserAccount(user)
	if err != nil {
		return err
	}

	handler := x.getHandler()
	inbounds := x.getConfig().InboundConfigs

	var errMessage string
	for _, inbound := range inbounds {
		account, isActive := isActiveInbound(inbound, user.GetInbounds(), proxySetting)
		if isActive {
			inbound.addUser(account)
			if err = handler.AddInboundUser(ctx, inbound.Tag, account); err != nil {
				log.Println(err)
				errMessage += "\n" + err.Error()
			}
		}
	}

	if err = x.GenerateConfigFile(); err != nil {
		log.Println(err)
	}

	if errMessage != "" {
		return errors.New("failed to add user:" + errMessage)
	}
	return nil
}

func (x *Xray) UpdateUser(ctx context.Context, user *common.User) error {
	proxySetting, err := setupUserAccount(user)
	if err != nil {
		return err
	}

	handler := x.getHandler()
	inbounds := x.getConfig().InboundConfigs

	var errMessage string

	for _, inbound := range inbounds {
		_ = handler.RemoveInboundUser(ctx, inbound.Tag, user.Email)
		account, isActive := isActiveInbound(inbound, user.GetInbounds(), proxySetting)
		if isActive {
			inbound.updateUser(account)
			err = handler.AddInboundUser(ctx, inbound.Tag, account)
			if err != nil {
				log.Println(err)
				errMessage += "\n" + err.Error()
			}
		} else {
			inbound.removeUser(user.GetEmail())
		}
	}

	if err = x.GenerateConfigFile(); err != nil {
		log.Println(err)
	}

	if errMessage != "" {
		return errors.New("failed to add user:" + errMessage)
	}
	return nil
}

func (x *Xray) RemoveUser(ctx context.Context, email string) {
	handler := x.getHandler()

	for _, inbound := range x.getConfig().InboundConfigs {
		inbound.removeUser(email)
		_ = handler.RemoveInboundUser(ctx, inbound.Tag, email)
	}

	if err := x.GenerateConfigFile(); err != nil {
		log.Println(err)
	}
}

func (x *Xray) SyncUsers(_ context.Context, _ []*common.User) error {
	return errors.New("not implemented method")
}
