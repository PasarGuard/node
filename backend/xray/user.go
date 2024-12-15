package xray

import (
	"context"
	"errors"
	"log"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/xtls/xray-core/proxy/shadowsocks"

	"github.com/m03ed/marzban-node-go/backend/xray/api"
	"github.com/m03ed/marzban-node-go/common"
)

func setupUserAccount(user *common.User) (api.ProxySettings, error) {
	settings := api.ProxySettings{}

	if user.Proxies.Vmess != nil && user.Proxies.Vmess.Id != "" {
		settings.Vmess = &api.VMessAccount{
			BaseAccount: api.BaseAccount{
				Email: user.GetEmail(),
				Level: uint32(0),
			},
		}
		id, err := uuid.Parse(user.Proxies.Vmess.Id)
		if err != nil {
			return settings, err
		}
		settings.Vmess.ID = id
	}

	if user.Proxies.Vless != nil && user.Proxies.Vless.Id != "" {
		settings.Vless = &api.VLESSAccount{
			BaseAccount: api.BaseAccount{
				Email: user.GetEmail(),
				Level: uint32(0),
			},
			Flow: api.XTLSFlows(user.Proxies.Vless.Flow),
		}
		id, err := uuid.Parse(user.Proxies.Vmess.Id)
		if err != nil {
			return settings, err
		}
		settings.Vless.ID = id
	}

	if user.Proxies.Trojan != nil && user.Proxies.Trojan.Password != "" {
		settings.Trojan = &api.TrojanAccount{
			BaseAccount: api.BaseAccount{
				Email: user.GetEmail(),
				Level: uint32(0),
			},
			Password: user.Proxies.Trojan.Password,
		}
	}

	if user.Proxies.Shadowsocks != nil && user.Proxies.Shadowsocks.Password != "" {
		settings.Shadowsocks = &api.ShadowsocksAccount{
			BaseAccount: api.BaseAccount{
				Email: user.GetEmail(),
				Level: uint32(0),
			},
			Password: user.Proxies.Shadowsocks.Password,
		}
		if v, ok := shadowsocks.CipherType_value[user.Proxies.Shadowsocks.Method]; ok {
			settings.Shadowsocks.Method = shadowsocks.CipherType(v)
		} else {
			settings.Shadowsocks.Method = shadowsocks.CipherType_NONE
		}

		settings.Shadowsocks2022 = &api.Shadowsocks2022Account{
			BaseAccount: api.BaseAccount{
				Email: user.GetEmail(),
				Level: uint32(0),
			},
			Key: user.Proxies.Shadowsocks.Password,
		}
	}

	return settings, nil
}

func IsActiveInbound(inbound *Inbound, user *common.User, settings api.ProxySettings) (api.Account, bool) {
	if slices.Contains(user.GetInbounds(), inbound.Tag) {
		switch inbound.Protocol {
		case Vless:
			account := *settings.Vless
			if api.XTLSFlows(user.GetProxies().GetVless().GetFlow()) == api.VISION {
				network, networkOk := inbound.StreamSettings["network"].(string)
				tls, tlsOk := inbound.StreamSettings["security"].(string)

				headerMap, headerMapOk := inbound.StreamSettings["header"].(map[string]interface{})
				headerType, headerTypeOk := "", false
				if headerMapOk {
					headerType, headerTypeOk = headerMap["Type"].(string)
				}

				if networkOk && (network == "tcp" || network == "kcp") {
					if !(tlsOk && (tls == "tls" || tls == "reality")) || (headerTypeOk && headerType == "http") {
						account.Flow = api.NONE
					}
				} else if headerTypeOk && headerType == "http" {
					account.Flow = api.NONE
				} else {
					account.Flow = api.NONE
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
	inbounds := x.getConfig().Inbounds

	var errMessage string
	for _, inbound := range inbounds {
		account, isActive := IsActiveInbound(inbound, user, proxySetting)
		if isActive {
			if err = handler.AddInboundUser(ctx, inbound.Tag, account); err != nil {
				log.Println(err)
				errMessage += "\n" + err.Error()
			}
		}
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
	inbounds := x.getConfig().Inbounds

	var errMessage string
	var activeInbounds []string

	for _, inbound := range inbounds {
		account, isActive := IsActiveInbound(inbound, user, proxySetting)
		if isActive {
			activeInbounds = append(activeInbounds, inbound.Tag)
			err = handler.AddInboundUser(ctx, inbound.Tag, account)
			if err != nil {
				log.Println(err)
				errMessage += "\n" + err.Error()
			}
		}
	}

	for _, inbound := range inbounds {
		if !slices.Contains(activeInbounds, inbound.Tag) {
			_ = handler.RemoveInboundUser(ctx, inbound.Tag, user.Email)
		}
	}

	if errMessage != "" {
		return errors.New("failed to add user:" + errMessage)
	}
	return nil
}

func (x *Xray) RemoveUser(ctx context.Context, email string) {
	handler := x.getHandler()

	for _, inbound := range x.getConfig().Inbounds {
		_ = handler.RemoveInboundUser(ctx, inbound.Tag, email)
	}
}
