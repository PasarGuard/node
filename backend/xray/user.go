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
	if user.GetProxies().GetVmess() != nil {
		vmessAccount, err := api.NewVmessAccount(user)
		if err != nil {
			return settings, err
		}
		settings.Vmess = vmessAccount
	}

	if user.GetProxies().GetVless() != nil {
		vlessAccount, err := api.NewVlessAccount(user)
		if err != nil {
			return settings, err
		}
		settings.Vless = vlessAccount
	}

	if user.GetProxies().GetTrojan() != nil {
		settings.Trojan = api.NewTrojanAccount(user)
	}

	if user.GetProxies().GetTrojan() != nil {
		settings.Shadowsocks = api.NewShadowsocksTcpAccount(user)
		settings.Shadowsocks2022 = api.NewShadowsocksAccount(user)
	}

	return settings, nil
}

func isActiveInbound(inbound *Inbound, inbounds []string, settings api.ProxySettings) (api.Account, bool) {
	if slices.Contains(inbounds, inbound.Tag) {
		switch inbound.Protocol {
		case Vless:
			if settings.Vless == nil {
				return nil, false
			}

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
			if settings.Vmess == nil {
				return nil, false
			}
			return settings.Vmess, true

		case Trojan:
			if settings.Trojan == nil {
				return nil, false
			}
			return settings.Trojan, true

		case Shadowsocks:
			method, methodOk := inbound.Settings["method"].(string)
			if methodOk && strings.HasPrefix("2022-blake3", method) {
				if settings.Shadowsocks2022 == nil {
					return nil, false
				}
				return settings.Shadowsocks2022, true
			}
			if settings.Shadowsocks == nil {
				return nil, false
			}
			return settings.Shadowsocks, true
		}
	}
	return nil, false
}

func (x *Xray) SyncUser(ctx context.Context, user *common.User) error {
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

func (x *Xray) SyncUsers(_ context.Context, _ []*common.User) error {
	return errors.New("not implemented method")
}
