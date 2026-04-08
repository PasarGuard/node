package wireguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config represents the WireGuard configuration
type Config struct {
	InterfaceName string   `json:"interface_name"`
	PrivateKey    string   `json:"private_key"`
	PreSharedKey  string   `json:"pre_shared_key,omitempty"`
	ListenPort    int      `json:"listen_port"`
	Address       []string `json:"address"`

	privateKeyValue   wgtypes.Key
	privateKeySet     bool
	presharedKeyValue *wgtypes.Key
	presharedKeySet   bool

	mu sync.RWMutex
}

// PeerInfo stores information about a WireGuard peer
type PeerInfo struct {
	Email      string      `json:"email"`
	PublicKey  wgtypes.Key `json:"public_key"`
	AllowedIPs []net.IPNet `json:"allowed_ips"`
}

func clonePeerInfo(peer *PeerInfo) *PeerInfo {
	if peer == nil {
		return nil
	}

	return &PeerInfo{
		Email:      peer.Email,
		PublicKey:  peer.PublicKey,
		AllowedIPs: append([]net.IPNet(nil), peer.AllowedIPs...),
	}
}

// NewConfig creates a new WireGuard configuration from JSON
func NewConfig(config string) (*Config, error) {
	var wgConfig Config
	err := json.Unmarshal([]byte(config), &wgConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if wgConfig.InterfaceName == "" {
		wgConfig.InterfaceName = "wg0"
	}

	if wgConfig.ListenPort <= 0 {
		wgConfig.ListenPort = 51820
	}

	return &wgConfig, nil
}

// InterfaceNetworks returns CIDR prefixes parsed from the node's core `address` list.
// Used to restrict peer AllowedIPs to subnets this interface actually serves.
func (c *Config) InterfaceNetworks() []*net.IPNet {
	if c == nil {
		return nil
	}
	var out []*net.IPNet
	for _, addr := range c.Address {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			continue
		}
		out = append(out, ipNet)
	}
	return out
}

// GetPrivateKey returns the parsed WireGuard private key.
// The parsed key is stored in memory and reused after first successful parse.
func (c *Config) GetPrivateKey() (wgtypes.Key, error) {
	c.mu.RLock()
	if c.privateKeySet {
		key := c.privateKeyValue
		c.mu.RUnlock()
		return key, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.privateKeySet {
		return c.privateKeyValue, nil
	}

	if c.PrivateKey == "" {
		// Return Error
		return wgtypes.Key{}, errors.New("private key is empty")
	}

	key, err := wgtypes.ParseKey(c.PrivateKey)
	if err != nil {
		return wgtypes.Key{}, err
	}
	c.privateKeyValue = key
	c.privateKeySet = true
	return key, nil
}

// GetPreSharedKey parses and caches the pre-shared key, optionally returning nil if not set.
func (c *Config) GetPreSharedKey() (*wgtypes.Key, error) {
	c.mu.RLock()
	if c.presharedKeySet {
		c.mu.RUnlock()
		return c.presharedKeyValue, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.presharedKeySet {
		return c.presharedKeyValue, nil
	}

	if c.PreSharedKey == "" {
		c.presharedKeySet = true
		c.presharedKeyValue = nil
		return nil, nil
	}

	key, err := wgtypes.ParseKey(c.PreSharedKey)
	if err != nil {
		return nil, err
	}
	c.presharedKeyValue = &key
	c.presharedKeySet = true
	return &key, nil
}

// GenerateKeyPair generates a new WireGuard key pair
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}

	return privKey.String(), privKey.PublicKey().String(), nil
}
