package xray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"
)

// setupUserAccount builds the user's account for every protocol it has usable
// credentials for. wireguardErr reports WireGuard settings that carry a key but
// are invalid; the other accounts are still set up.
func setupUserAccount(user *common.User) (settings api.ProxySettings, wireguardErr error) {
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

	// Panels send an empty WireGuard message for every user without WireGuard
	// keys, so a message without a public key means no WireGuard account.
	if user.GetProxies().GetWireguard().GetPublicKey() != "" {
		if wgAccount, err := api.NewWireguardAccount(user); err == nil {
			settings.Wireguard = wgAccount
		} else {
			wireguardErr = err
		}
	}

	return settings, wireguardErr
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

func wireguardInboundNetwork(address string) *net.IPNet {
	address = strings.TrimSpace(address)
	if _, network, err := net.ParseCIDR(address); err == nil {
		return network
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return nil
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return &net.IPNet{IP: ipv4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func (i *Inbound) wireguardAccountForInbound(account *api.WireguardAccount) (*api.WireguardAccount, bool) {
	addresses, hasAddress := i.Settings["address"]
	var interfaceNets []*net.IPNet
	switch values := addresses.(type) {
	case []any:
		for _, address := range values {
			if value, ok := address.(string); ok {
				if network := wireguardInboundNetwork(value); network != nil {
					interfaceNets = append(interfaceNets, network)
				}
			}
		}
	case []string:
		for _, address := range values {
			if network := wireguardInboundNetwork(address); network != nil {
				interfaceNets = append(interfaceNets, network)
			}
		}
	}

	allowed := make([]string, 0, len(account.AllowedIPs))
	for _, cidr := range account.AllowedIPs {
		_, peerNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("skipping wireguard user %s with invalid peer IP %s: %v", account.GetEmail(), cidr, err)
			return nil, false
		}
		if !hasAddress {
			allowed = append(allowed, cidr)
			continue
		}
		for _, pool := range interfaceNets {
			peerBits, _ := peerNet.Mask.Size()
			poolBits, _ := pool.Mask.Size()
			if len(peerNet.IP) == len(pool.IP) && pool.Contains(peerNet.IP) && peerBits >= poolBits {
				allowed = append(allowed, cidr)
				break
			}
		}
	}
	if len(allowed) == 0 {
		return nil, false
	}
	filtered := *account
	filtered.AllowedIPs = allowed
	return &filtered, true
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

		case Wireguard:
			if settings.Wireguard == nil {
				return nil, false
			}
			account, ok := inbound.wireguardAccountForInbound(settings.Wireguard)
			if !ok {
				return nil, false
			}
			return account, true
		}
	}
	return nil, false
}

func wireguardPeerReplaced(current, next *api.WireguardAccount) bool {
	return current.PublicKey != next.PublicKey || (current.PreSharedKey != "" && next.PreSharedKey == "")
}

func (i *Inbound) removeBeforeAdd(account api.Account) bool {
	next, ok := account.(*api.WireguardAccount)
	if !ok {
		return true
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	// AddUser в Xray обновляет пир по публичному ключу: старый ключ остаётся авторизованным,
	// а пустой PSK не затирает прежний, поэтому в этих случаях пир нужно удалить явно
	current, ok := i.clients[next.GetEmail()].(*api.WireguardAccount)
	return ok && wireguardPeerReplaced(current, next)
}

func (x *Xray) SyncUser(ctx context.Context, user *common.User) error {
	x.syncMu.Lock()
	defer x.syncMu.Unlock()

	// The request may have been abandoned while it queued behind a restart or
	// another sync; running it now would only cause pointless work.
	if err := ctx.Err(); err != nil {
		return err
	}

	proxySetting, wireguardErr := setupUserAccount(user)

	handler := x.handler
	inbounds := x.config.InboundConfigs

	var errMessage strings.Builder

	userInbounds := user.GetInbounds()

	for _, inbound := range inbounds {
		if inbound.exclude || !inbound.canHoldUsers() {
			continue
		}

		// Invalid WireGuard settings must not drop the live peer of an inbound
		// the user stays on; its other inbounds are still applied.
		if wireguardErr != nil && inbound.Protocol == Wireguard && slices.Contains(userInbounds, inbound.Tag) {
			err := fmt.Errorf("wireguard user %s on inbound %s: %w", user.GetEmail(), inbound.Tag, wireguardErr)
			log.Println(err)
			errMessage.WriteString("\n" + err.Error())
			continue
		}

		account, isActive := isActiveInbound(inbound, userInbounds, proxySetting)
		if isActive && inbound.hasAccount(account) {
			continue
		}

		if isActive {
			removeFirst := inbound.removeBeforeAdd(account)
			if removeFirst {
				if err := handler.RemoveInboundUser(ctx, inbound.Tag, user.GetEmail()); err != nil && inbound.Protocol == Wireguard {
					return fmt.Errorf("failed to remove wireguard user %s from inbound %s: %w", user.GetEmail(), inbound.Tag, err)
				}
			}
			inbound.updateUser(account)
			err := handler.AddInboundUser(ctx, inbound.Tag, accountForAPI(inbound, account))
			if err != nil {
				inbound.removeUser(user.GetEmail())
				log.Println(err)
				errMessage.WriteString("\n" + err.Error())
			}
		} else {
			_ = handler.RemoveInboundUser(ctx, inbound.Tag, user.GetEmail())
			inbound.removeUser(user.GetEmail())
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

	// The request may have been abandoned while it queued behind a restart or
	// another sync; running it now would only cause pointless work.
	if err := ctx.Err(); err != nil {
		return err
	}

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

	// The new core is already booting. Rolling back because the panel gave up
	// on its RPC timeout would restart xray a second time and leave it on the
	// old users, so wait for it regardless; Shutdown still ends the wait, since
	// checkXrayStatus sees the core stop.
	readyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fullSyncReadyTimeout)
	defer cancel()
	if err := x.checkXrayStatus(readyCtx); err != nil {
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

	// The request may have been abandoned while it queued behind a restart or
	// another sync; running it now would only cause pointless work.
	if err := ctx.Err(); err != nil {
		return err
	}

	handler := x.handler
	inboundByTag, updates := x.config.buildInboundUpdates(users)
	var errMessage strings.Builder

	for tag, update := range updates {
		removeEmails := make([]string, 0, len(update.removeEmailSet))
		for email := range update.removeEmailSet {
			removeEmails = append(removeEmails, email)
		}

		inbound := inboundByTag[tag]
		accounts := inbound.changedAccounts(update.accounts)
		removeFirst := make([]bool, len(accounts))
		for n, account := range accounts {
			removeFirst[n] = inbound.removeBeforeAdd(account)
		}
		inbound.updateUsers(nil, removeEmails)

		for _, email := range removeEmails {
			handler.RemoveInboundUser(ctx, tag, email)
		}

		for n, account := range accounts {
			if removeFirst[n] {
				if err := handler.RemoveInboundUser(ctx, tag, account.GetEmail()); err != nil && inbound.Protocol == Wireguard {
					removeErr := fmt.Errorf("failed to remove wireguard user %s from inbound %s: %w", account.GetEmail(), tag, err)
					log.Println(removeErr)
					errMessage.WriteString("\n" + removeErr.Error())
					continue
				}
			}
			if err := handler.AddInboundUser(ctx, tag, accountForAPI(inbound, account)); err != nil {
				inbound.removeUser(account.GetEmail())
				log.Println(err)
				errMessage.WriteString("\n" + err.Error())
			} else {
				inbound.updateUser(account)
			}
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

	// The request may have been abandoned while it queued behind a restart or
	// another sync; running it now would only cause pointless work.
	if err := ctx.Err(); err != nil {
		return err
	}

	candidate, err := x.config.Clone()
	if err != nil {
		return err
	}

	candidate.updateUsers(users)
	return x.applyConfigWithRestart(ctx, candidate)
}
