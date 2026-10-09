package api

import (
	"fmt"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/wireguard"

	"github.com/pasarguard/node/common"
)

// WireguardAccount is an Xray UserManager WireGuard peer.
type WireguardAccount struct {
	BaseAccount
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	AllowedIPs   []string `json:"allowedIPs"`
}

func (wa *WireguardAccount) Message() (*serial.TypedMessage, error) {
	return ToTypedMessage(&wireguard.PeerConfig{
		PublicKey:    wa.PublicKey,
		PreSharedKey: wa.PreSharedKey,
		AllowedIps:   wa.AllowedIPs,
	})
}

func NewWireguardAccount(user *common.User) (*WireguardAccount, error) {
	wg := user.GetProxies().GetWireguard()
	if wg == nil || wg.GetPublicKey() == "" {
		return nil, fmt.Errorf("wireguard public_key is required")
	}

	pubHex, err := WireguardKeyToHex(wg.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("wireguard public_key: %w", err)
	}

	pskHex := ""
	if psk := wg.GetPreSharedKey(); psk != "" {
		pskHex, err = WireguardKeyToHex(psk)
		if err != nil {
			return nil, fmt.Errorf("wireguard pre_shared_key: %w", err)
		}
	}

	allowed := wg.GetPeerIps()
	if len(allowed) == 0 {
		return nil, fmt.Errorf("wireguard peer_ips is required")
	}

	return &WireguardAccount{
		BaseAccount: BaseAccount{
			Email: user.GetEmail(),
			Level: 0,
		},
		PublicKey:    pubHex,
		PreSharedKey: pskHex,
		AllowedIPs:   allowed,
	}, nil
}
