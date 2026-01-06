package xray

import (
	"context"
	"errors"
	"log"
	"slices"
	"strings"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
)

func setupUserAccount(user *common.User) (api.ProxySettings, error) {
	settings := api.ProxySettings{}
	if user.GetProxies().GetVmess() != nil {
		if vmessAccount, err := api.NewVmessAccount(user); err == nil {
			settings.Vmess = vmessAccount
		}
	}

	if user.GetProxies().GetVless() != nil {
		if vlessAccount, err := api.NewVlessAccount(user); err == nil {
			settings.Vless = vlessAccount
		}
	}

	if user.GetProxies().GetTrojan() != nil {
		settings.Trojan = api.NewTrojanAccount(user)
	}

	if user.GetProxies().GetShadowsocks() != nil {
		settings.Shadowsocks = api.NewShadowsocksTcpAccount(user)
		settings.Shadowsocks2022 = api.NewShadowsocksAccount(user)
	}

	return settings, nil
}

func checkVless(inbound *Inbound, account api.VlessAccount) api.VlessAccount {
	if account.Flow != "" {

		networkType, ok := inbound.StreamSettings["network"]
		if !ok || !(networkType == "tcp" || networkType == "raw" || networkType == "kcp") {
			account.Flow = ""
			return account
		}

		securityType, ok := inbound.StreamSettings["security"]
		if !ok || !(securityType == "tls" || securityType == "reality") {
			account.Flow = ""
			return account
		}

		rawMap, ok := inbound.StreamSettings["rawSettings"].(map[string]interface{})
		if !ok {
			rawMap, ok = inbound.StreamSettings["tcpSettings"].(map[string]interface{})
			if !ok {
				return account
			}
		}

		headerMap, ok := rawMap["header"].(map[string]interface{})
		if !ok {
			return account
		}

		headerType, ok := headerMap["Type"].(string)
		if !ok {
			return account
		}

		if headerType == "http" {
			account.Flow = ""
			return account
		}
	}
	return account
}

func checkShadowsocks2022(method string, account api.ShadowsocksAccount) api.ShadowsocksAccount {
	account.Password = common.EnsureBase64Password(account.Password, method)

	return account
}

func isActiveInbound(inbound *Inbound, inbounds []string, settings api.ProxySettings) (api.Account, bool) {
	if slices.Contains(inbounds, inbound.Tag) {
		switch inbound.Protocol {
		case Vless:
			if settings.Vless == nil {
				return nil, false
			}
			account := checkVless(inbound, *settings.Vless)
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
			method, ok := inbound.Settings["method"].(string)
			if ok && strings.HasPrefix(method, "2022-blake3") {
				if settings.Shadowsocks2022 == nil {
					return nil, false
				}
				account := checkShadowsocks2022(method, *settings.Shadowsocks2022)

				return &account, true
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

	handler := x.handler
	inbounds := x.config.InboundConfigs

	var errMessage string

	userInbounds := user.GetInbounds()

	for _, inbound := range inbounds {
		if inbound.exclude {
			continue
		}

		_ = handler.RemoveInboundUser(ctx, inbound.Tag, user.Email)
		account, isActive := isActiveInbound(inbound, userInbounds, proxySetting)
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

	if errMessage != "" {
		return errors.New("failed to add user:" + errMessage)
	}
	return nil
}

func (x *Xray) SyncUsers(_ context.Context, users []*common.User) error {
	x.config.syncUsers(users)
	if err := x.Restart(); err != nil {
		return err
	}
	if err := x.checkXrayStatus(); err != nil {
		return err
	}
	return nil
}
