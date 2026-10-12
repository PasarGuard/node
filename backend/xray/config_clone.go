package xray

import (
	"encoding/json"
	"fmt"

	"github.com/pasarguard/node/backend/xray/api"
)

func cloneAccount(account api.Account) api.Account {
	switch a := account.(type) {
	case *api.VmessAccount:
		copy := *a
		return &copy
	case *api.VlessAccount:
		copy := *a
		return &copy
	case *api.TrojanAccount:
		copy := *a
		return &copy
	case *api.ShadowsocksTcpAccount:
		copy := *a
		return &copy
	case *api.ShadowsocksAccount:
		copy := *a
		return &copy
	case *api.HysteriaAccount:
		copy := *a
		return &copy
	default:
		return account
	}
}

func cloneClients(clients map[string]api.Account) map[string]api.Account {
	if clients == nil {
		return make(map[string]api.Account)
	}

	out := make(map[string]api.Account, len(clients))
	for email, account := range clients {
		out[email] = cloneAccount(account)
	}
	return out
}

func (c *Config) Clone() (*Config, error) {
	if c == nil {
		return nil, fmt.Errorf("xray config is nil")
	}

	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal xray config clone: %w", err)
	}

	var cloned Config
	if err := json.Unmarshal(data, &cloned); err != nil {
		return nil, fmt.Errorf("unmarshal xray config clone: %w", err)
	}

	originalByTag := make(map[string]*Inbound, len(c.InboundConfigs))
	for _, inbound := range c.InboundConfigs {
		if inbound != nil {
			originalByTag[inbound.Tag] = inbound
		}
	}

	for _, inbound := range cloned.InboundConfigs {
		if inbound == nil {
			continue
		}

		original := originalByTag[inbound.Tag]
		if original == nil {
			inbound.clients = make(map[string]api.Account)
			continue
		}

		original.mu.RLock()
		inbound.exclude = original.exclude
		inbound.clients = cloneClients(original.clients)
		original.mu.RUnlock()
	}

	return &cloned, nil
}
