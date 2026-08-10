package xray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type inboundUserHandler interface {
	AddInboundUser(context.Context, string, api.Account) error
	RemoveInboundUser(context.Context, string, string) error
}

func (x *Xray) inboundUserHandler() inboundUserHandler {
	if x.userHandler != nil {
		return x.userHandler
	}
	return x.handler
}

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

// removeInboundUser treats an already-absent runtime user as a successful
// idempotent revoke, but never hides transport/core errors. A caller must not
// report a revoked credential while Xray still accepts it.
func removeInboundUser(ctx context.Context, handler inboundUserHandler, tag, email string) error {
	err := handler.RemoveInboundUser(ctx, tag, email)
	if isBenignUserRemovalError(err) {
		return nil
	}
	return err
}

func isBenignUserRemovalError(err error) bool {
	if err == nil || status.Code(err) == codes.NotFound {
		return true
	}
	// Xray's HandlerService historically reports both of these idempotent
	// conditions as Unknown rather than NotFound. An absent user cannot keep a
	// credential alive, and API/non-user-manager inbounds cannot contain one.
	// All transport and runtime failures stay visible to the caller.
	if status.Code(err) != codes.Unknown {
		return false
	}
	message := strings.ToLower(status.Convert(err).Message())
	return strings.Contains(message, "not found") || strings.Contains(message, "not a usermanager")
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
	x.syncMu.Lock()
	defer x.syncMu.Unlock()

	proxySetting, err := setupUserAccount(user)
	if err != nil {
		return err
	}

	handler := x.inboundUserHandler()
	inbounds := x.config.InboundConfigs

	var errMessage strings.Builder

	userInbounds := user.GetInbounds()

	for _, inbound := range inbounds {
		if inbound.exclude {
			continue
		}

		if err := removeInboundUser(ctx, handler, inbound.Tag, user.Email); err != nil {
			return fmt.Errorf("failed to remove user %q from inbound %q: %w", user.Email, inbound.Tag, err)
		}
		// Keep the restart snapshot aligned with every confirmed runtime
		// mutation. In particular, a failed replacement must not leave the old
		// credential in the snapshot where a health restart could resurrect it.
		inbound.removeUser(user.Email)
		account, isActive := isActiveInbound(inbound, userInbounds, proxySetting)
		if isActive {
			err = handler.AddInboundUser(ctx, inbound.Tag, accountForAPI(inbound, account))
			if err != nil {
				log.Println(err)
				errMessage.WriteString("\n" + err.Error())
			} else {
				inbound.updateUser(account)
			}
		}
	}

	if errMessage.String() != "" {
		return errors.New("failed to add user:" + errMessage.String())
	}
	return nil
}

func (x *Xray) SyncUsers(ctx context.Context, users []*common.User) error {
	x.syncMu.Lock()
	defer x.syncMu.Unlock()

	candidate, err := x.config.Clone()
	if err != nil {
		return err
	}

	candidate.syncUsers(users)
	return x.applyConfigWithRestart(ctx, candidate)
}

func (x *Xray) applyConfigWithRestart(ctx context.Context, candidate *Config) error {
	previous := x.config

	if err := x.restartCoreWithConfig(candidate); err != nil {
		if restoreErr := x.restorePreviousConfig(previous); restoreErr != nil {
			return fmt.Errorf("%w; failed to restore previous xray config: %v", err, restoreErr)
		}
		return err
	}

	if err := x.checkXrayStatus(ctx); err != nil {
		if restoreErr := x.restorePreviousConfig(previous); restoreErr != nil {
			return fmt.Errorf("%w; failed to restore previous xray config: %v", err, restoreErr)
		}
		return err
	}

	x.setConfig(candidate)
	return nil
}

func (x *Xray) restorePreviousConfig(previous *Config) error {
	if previous == nil {
		return errors.New("previous xray config is nil")
	}

	log.Println("restoring previous xray config after failed restart")
	if err := x.restartCoreWithConfig(previous); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := x.checkXrayStatus(ctx); err != nil {
		return err
	}

	x.setConfig(previous)
	return nil
}

func (x *Xray) UpdateUsers(ctx context.Context, users []*common.User) error {
	x.syncMu.Lock()
	defer x.syncMu.Unlock()

	handler := x.inboundUserHandler()
	inboundByTag, updates := x.config.buildInboundUpdates(users)
	var errMessage strings.Builder

	for tag, update := range updates {
		removeEmails := make([]string, 0, len(update.removeEmailSet))
		for email := range update.removeEmailSet {
			removeEmails = append(removeEmails, email)
		}
		sort.Strings(removeEmails)

		inbound := inboundByTag[tag]

		for _, email := range removeEmails {
			if err := removeInboundUser(ctx, handler, tag, email); err != nil {
				return fmt.Errorf("failed to remove user %q from inbound %q: %w", email, tag, err)
			}
			inbound.removeUser(email)
		}

		for _, account := range update.accounts {
			email := account.GetEmail()
			if err := removeInboundUser(ctx, handler, tag, email); err != nil {
				return fmt.Errorf("failed to replace user %q in inbound %q: %w", email, tag, err)
			}
			inbound.removeUser(email)
			if err := handler.AddInboundUser(ctx, tag, accountForAPI(inbound, account)); err != nil {
				log.Println(err)
				errMessage.WriteString("\n" + err.Error())
				continue
			}
			inbound.updateUser(account)
		}
	}

	if errMessage.String() != "" {
		return errors.New("failed to update users:" + errMessage.String())
	}

	return nil
}

func (x *Xray) UpdateUsersAndRestart(ctx context.Context, users []*common.User) error {
	x.syncMu.Lock()
	defer x.syncMu.Unlock()

	candidate, err := x.config.Clone()
	if err != nil {
		return err
	}

	candidate.updateUsers(users)
	return x.applyConfigWithRestart(ctx, candidate)
}
