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

	if user.GetProxies().GetHysteria() != nil {
		settings.Hysteria = api.NewHysteriaAccount(user)
	}

	return settings, nil
}

func inboundFlow(inbound *Inbound) string {
	if inbound == nil || inbound.Settings == nil {
		return ""
	}
	flow, _ := inbound.Settings["flow"].(string)
	return flow
}

func accountForAPI(inbound *Inbound, account api.Account) api.Account {
	vlessAccount, ok := account.(*api.VlessAccount)
	if !ok {
		return account
	}

	overrideFlow := inboundFlow(inbound)
	if overrideFlow == "" {
		return account
	}

	copy := *vlessAccount
	copy.Flow = overrideFlow
	return &copy
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
			return settings.Vless, true

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

		case Hysteria:
			if settings.Hysteria == nil {
				return nil, false
			}
			return settings.Hysteria, true
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
			err = handler.AddInboundUser(ctx, inbound.Tag, accountForAPI(inbound, account))
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

func (x *Xray) SyncUsers(ctx context.Context, users []*common.User) error {
	x.config.syncUsers(users)
	if err := x.Restart(); err != nil {
		return err
	}
	if err := x.checkXrayStatus(ctx); err != nil {
		return err
	}
	return nil
}

func (x *Xray) UpdateUsers(ctx context.Context, users []*common.User) error {
	handler := x.handler
	inboundByTag, updates := x.config.buildInboundUpdates(users)
	var errMessage string

	for tag, update := range updates {
		removeEmails := make([]string, 0, len(update.removeEmailSet))
		for email := range update.removeEmailSet {
			removeEmails = append(removeEmails, email)
		}

		inbound := inboundByTag[tag]
		inbound.updateUsers(update.accounts, removeEmails)

		for _, email := range removeEmails {
			handler.RemoveInboundUser(ctx, tag, email)
		}

		for _, account := range update.accounts {
			_ = handler.RemoveInboundUser(ctx, tag, account.GetEmail())
			if err := handler.AddInboundUser(ctx, tag, accountForAPI(inbound, account)); err != nil {
				log.Println(err)
				errMessage += "\n" + err.Error()
			}
		}
	}

	if errMessage != "" {
		return errors.New("failed to update users:" + errMessage)
	}

	return nil
}

func (x *Xray) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	x.config.updateUsers(users)
	if err := x.Restart(); err != nil {
		return err
	}
	if err := x.checkXrayStatus(ctx); err != nil {
		return err
	}
	return nil
}
