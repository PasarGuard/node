package wireguard

import (
	"fmt"
	"log"
	"net"
	"slices"
	"sort"
	"time"

	"github.com/pasarguard/node/common"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	tempKeepAlive = time.Duration(0)
	keepAlive     = &tempKeepAlive
)

func buildAddConfig(publicKey wgtypes.Key, allowedIPs []net.IPNet, presharedKey *wgtypes.Key) wgtypes.PeerConfig {
	config := wgtypes.PeerConfig{
		PublicKey:                   publicKey,
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: keepAlive,
	}
	if presharedKey != nil {
		config.PresharedKey = presharedKey
	}
	return config
}

func buildRemoveConfig(publicKey wgtypes.Key) wgtypes.PeerConfig {
	return wgtypes.PeerConfig{PublicKey: publicKey, Remove: true}
}

type DesiredPeer struct {
	Email         string
	PublicKey     string
	ParsedKey     wgtypes.Key
	AllowedIPNets []net.IPNet
}

type SyncDiff struct {
	RemoveKeys  []string
	UpsertPeers []*PeerInfo
	PeerConfigs []wgtypes.PeerConfig
	TargetPeers map[string]*PeerInfo
	Changed     bool
}

func (wg *WireGuard) buildSyncDiff(
	existingPeers map[string]*PeerInfo,
	desiredPeers map[string]*DesiredPeer,
) (*SyncDiff, error) {
	targetPeers := make(map[string]*PeerInfo, len(desiredPeers))
	for key, desired := range desiredPeers {
		targetPeers[key] = &PeerInfo{
			Email:      desired.Email,
			PublicKey:  desired.ParsedKey,
			AllowedIPs: desired.AllowedIPNets,
		}
	}

	removeSet := make(map[string]*PeerInfo)
	upsertByKey := make(map[string]*PeerInfo)
	var peerConfigs []wgtypes.PeerConfig
	psk, _ := wg.config.GetPreSharedKey()
	for key, existing := range existingPeers {
		target, exists := targetPeers[key]
		if !exists {
			removeSet[key] = existing
			continue
		}

		ipnetsEqual := true
		if len(existing.AllowedIPs) != len(target.AllowedIPs) {
			ipnetsEqual = false
		} else {
			for i := range existing.AllowedIPs {
				if existing.AllowedIPs[i].String() != target.AllowedIPs[i].String() {
					ipnetsEqual = false
					break
				}
			}
		}

		if existing.Email != target.Email || !ipnetsEqual {
			if !ipnetsEqual {
				config, err := buildAddConfigFromPeerInfo(target, psk)
				if err != nil {
					log.Printf("quarantining peer update %s due to config error: %v", target.Email, err)
					continue
				}
				config.ReplaceAllowedIPs = true
				peerConfigs = append(peerConfigs, config)
			}
			upsertByKey[key] = target
		}
	}

	for key, target := range targetPeers {
		if _, exists := existingPeers[key]; !exists {
			config, err := buildAddConfigFromPeerInfo(target, psk)
			if err != nil {
				log.Printf("quarantining peer %s due to config error: %v", target.Email, err)
				continue
			}
			upsertByKey[key] = target
			peerConfigs = append(peerConfigs, config)
		}
	}

	removeKeys, removeConfigs := buildRemoveConfigsForPeers(removeSet)

	peerConfigs = append(peerConfigs, removeConfigs...)

	upsertKeys := make([]string, 0, len(upsertByKey))
	for key := range upsertByKey {
		upsertKeys = append(upsertKeys, key)
	}
	sort.Strings(upsertKeys)

	upsertPeers := make([]*PeerInfo, 0, len(upsertKeys))
	for _, key := range upsertKeys {
		upsertPeers = append(upsertPeers, upsertByKey[key])
	}

	changed := len(removeKeys) > 0 || len(upsertPeers) > 0

	return &SyncDiff{
		RemoveKeys:  removeKeys,
		UpsertPeers: upsertPeers,
		PeerConfigs: peerConfigs,
		TargetPeers: targetPeers,
		Changed:     changed,
	}, nil
}

// buildTargetPeerConfigs converts targetPeers into WireGuard peer configs.
// Peers that fail key/IP parsing are quarantined (logged and skipped).
// Returns the config slice AND the set of public keys that were successfully
// built, so callers can filter the peerStore upsert list accordingly — the
// store must only contain peers that were actually committed to the kernel.
func buildTargetPeerConfigs(targetPeers map[string]*PeerInfo, presharedKey *wgtypes.Key) ([]wgtypes.PeerConfig, map[string]struct{}) {
	keys := make([]string, 0, len(targetPeers))
	for key := range targetPeers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	configs := make([]wgtypes.PeerConfig, 0, len(keys))
	appliedKeys := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		config, err := buildAddConfigFromPeerInfo(targetPeers[key], presharedKey)
		if err != nil {
			log.Printf("quarantining startup peer %s due to config error: %v", targetPeers[key].Email, err)
			continue
		}
		configs = append(configs, config)
		appliedKeys[key] = struct{}{}
	}

	return configs, appliedKeys
}

// filterUpsertsByAppliedKeys returns only the peers whose public key appears in appliedKeys.
// This keeps the peerStore in sync with what was actually committed to the kernel;
// quarantined peers (bad key or IP) are excluded from both.
func filterUpsertsByAppliedKeys(upserts []*PeerInfo, appliedKeys map[string]struct{}) []*PeerInfo {
	if len(appliedKeys) == len(upserts) {
		return upserts // fast path: nobody was quarantined
	}
	filtered := make([]*PeerInfo, 0, len(appliedKeys))
	for _, p := range upserts {
		if _, ok := appliedKeys[p.PublicKey.String()]; ok {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func buildAddConfigFromPeerInfo(peer *PeerInfo, presharedKey *wgtypes.Key) (wgtypes.PeerConfig, error) {
	if len(peer.AllowedIPs) == 0 {
		return wgtypes.PeerConfig{}, fmt.Errorf("peer %s has no allowed IPs", peer.Email)
	}

	return buildAddConfig(peer.PublicKey, peer.AllowedIPs, presharedKey), nil
}

func peerIPAllowedOnInterface(peerNet *net.IPNet, ifaceNets []*net.IPNet) bool {
	if len(ifaceNets) == 0 {
		return true
	}
	for _, pool := range ifaceNets {
		if pool == nil || peerNet == nil {
			continue
		}
		if len(peerNet.IP) != len(pool.IP) {
			continue
		}
		if !pool.Contains(peerNet.IP) {
			continue
		}
		pPeer, _ := peerNet.Mask.Size()
		pPool, _ := pool.Mask.Size()
		if pPeer >= pPool {
			return true
		}
	}
	return false
}

func (wg *WireGuard) collectDesiredPeers(users []*common.User) (map[string]*DesiredPeer, error) {
	desiredPeers := make(map[string]*DesiredPeer)
	seenIPs := make(map[string]string)

	for _, user := range users {
		if !shouldIncludeUserInInterface(user, wg.config.InterfaceName) {
			continue
		}

		email := user.GetEmail()
		publicKey := user.GetProxies().GetWireguard().GetPublicKey()
		peerIps := user.GetProxies().GetWireguard().GetPeerIps()

		parsedKey, err := wgtypes.ParseKey(publicKey)
		if err != nil {
			log.Printf("quarantining user %s due to invalid public key: %v", email, err)
			continue
		}

		ifaceNets := wg.config.InterfaceNetworks()

		var allowedIPNets []net.IPNet
		var hasInvalidIP bool

		for _, peerIp := range peerIps {
			_, ipNet, err := net.ParseCIDR(peerIp)
			if err != nil {
				log.Printf("quarantining user %s due to invalid provided IP %s: %v", email, peerIp, err)
				hasInvalidIP = true
				break
			}

			if !peerIPAllowedOnInterface(ipNet, ifaceNets) {
				log.Printf(
					"skipping wireguard peer IP %s for user %s on interface %s (outside core address ranges)",
					peerIp,
					email,
					wg.config.InterfaceName,
				)
				continue
			}

			canonicalIP := ipNet.String()
			if existingEmail, exists := seenIPs[canonicalIP]; exists && existingEmail != email {
				return nil, fmt.Errorf("duplicate wireguard allowed IP %s assigned to users %s and %s", canonicalIP, existingEmail, email)
			}
			seenIPs[canonicalIP] = email
			allowedIPNets = append(allowedIPNets, *ipNet)
		}

		if hasInvalidIP || len(allowedIPNets) == 0 {
			continue
		}

		if existing, exists := desiredPeers[publicKey]; exists && existing.Email != email {
			return nil, fmt.Errorf("wireguard public key %s is assigned to multiple users: %s and %s", publicKey, existing.Email, email)
		}

		desiredPeers[publicKey] = &DesiredPeer{
			Email:         email,
			PublicKey:     publicKey,
			ParsedKey:     parsedKey,
			AllowedIPNets: allowedIPNets,
		}
	}

	return desiredPeers, nil
}

func buildRemoveConfigsForPeers(removeSet map[string]*PeerInfo) ([]string, []wgtypes.PeerConfig) {
	sortedKeys := make([]string, 0, len(removeSet))
	for key := range removeSet {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	var validRemoveKeys []string
	var peerConfigs []wgtypes.PeerConfig

	for _, key := range sortedKeys {
		publicKey, err := wgtypes.ParseKey(key)
		if err != nil {
			log.Printf("quarantining peer removal %s due to invalid key %q: %v", removeSet[key].Email, key, err)
			continue
		}
		peerConfigs = append(peerConfigs, buildRemoveConfig(publicKey))
		validRemoveKeys = append(validRemoveKeys, key)
	}

	return validRemoveKeys, peerConfigs
}

func shouldIncludeUserInInterface(user *common.User, interfaceName string) bool {
	return slices.Contains(user.GetInbounds(), interfaceName)
}

func normalizeUsers(users []*common.User) []*common.User {
	lastByEmail := make(map[string]*common.User, len(users))

	for _, user := range users {
		switch {
		case user == nil,
			user.GetEmail() == "",
			user.GetProxies() == nil,
			user.GetProxies().GetWireguard() == nil,
			user.GetProxies().GetWireguard().GetPublicKey() == "",
			len(user.GetProxies().GetWireguard().GetPeerIps()) == 0:
			continue
		}
		lastByEmail[user.GetEmail()] = user
	}

	normalized := make([]*common.User, 0, len(lastByEmail))
	for _, user := range lastByEmail {
		normalized = append(normalized, user)
	}

	return normalized
}
