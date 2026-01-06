package xray

import (
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"

	"github.com/pasarguard/node/backend/xray/api"
	"github.com/pasarguard/node/common"

	"github.com/xtls/xray-core/infra/conf"
)

type Protocol string

const (
	Vmess       = "vmess"
	Vless       = "vless"
	Trojan      = "trojan"
	Shadowsocks = "shadowsocks"
)

type Config struct {
	LogConfig        *conf.LogConfig        `json:"log"`
	RouterConfig     *conf.RouterConfig     `json:"routing"`
	DNSConfig        map[string]interface{} `json:"dns"`
	InboundConfigs   []*Inbound             `json:"inbounds"`
	OutboundConfigs  interface{}            `json:"outbounds"`
	Policy           *conf.PolicyConfig     `json:"policy"`
	API              *conf.APIConfig        `json:"api"`
	Metrics          map[string]interface{} `json:"metrics,omitempty"`
	Stats            Stats                  `json:"stats"`
	Reverse          map[string]interface{} `json:"reverse,omitempty"`
	FakeDNS          map[string]interface{} `json:"fakeDns,omitempty"`
	Observatory      map[string]interface{} `json:"observatory,omitempty"`
	BurstObservatory map[string]interface{} `json:"burstObservatory,omitempty"`
}

type Inbound struct {
	Tag            string                 `json:"tag"`
	Listen         string                 `json:"listen,omitempty"`
	Port           interface{}            `json:"port,omitempty"`
	Protocol       string                 `json:"protocol"`
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings map[string]interface{} `json:"streamSettings,omitempty"`
	Sniffing       interface{}            `json:"sniffing,omitempty"`
	Allocation     map[string]interface{} `json:"allocate,omitempty"`
	mu             sync.RWMutex
	exclude        bool
	clients        map[string]api.Account // Runtime-only map: email -> account (never serialized)
}

func (c *Config) syncUsers(users []*common.User) {
	for _, i := range c.InboundConfigs {
		if i.exclude {
			continue
		}
		i.syncUsers(users)
	}
}

func (i *Inbound) syncUsers(users []*common.User) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Clear existing clients map
	i.clients = make(map[string]api.Account)

	switch i.Protocol {
	case Vmess:
		for _, user := range users {
			if user.GetProxies().GetVmess() == nil {
				continue
			}
			if slices.Contains(user.Inbounds, i.Tag) {
				account, err := api.NewVmessAccount(user)
				if err != nil {
					log.Println("error for user", user.GetEmail(), ":", err)
					continue
				}
				i.clients[user.GetEmail()] = account
			}
		}

	case Vless:
		for _, user := range users {
			if user.GetProxies().GetVless() == nil {
				continue
			}
			if slices.Contains(user.Inbounds, i.Tag) {
				account, err := api.NewVlessAccount(user)
				if err != nil {
					log.Println("error for user", user.GetEmail(), ":", err)
					continue
				}
				newAccount := checkVless(i, *account)
				i.clients[user.GetEmail()] = &newAccount
			}
		}

	case Trojan:
		for _, user := range users {
			if user.GetProxies().GetTrojan() == nil {
				continue
			}
			if slices.Contains(user.Inbounds, i.Tag) {
				i.clients[user.GetEmail()] = api.NewTrojanAccount(user)
			}
		}

	case Shadowsocks:
		method, methodOk := i.Settings["method"].(string)
		if methodOk && strings.HasPrefix(method, "2022-blake3") {
			for _, user := range users {
				if user.GetProxies().GetShadowsocks() == nil {
					continue
				}
				if slices.Contains(user.Inbounds, i.Tag) {
					account := api.NewShadowsocksAccount(user)
					newAccount := checkShadowsocks2022(method, *account)
					i.clients[user.GetEmail()] = &newAccount
				}
			}
		} else {
			for _, user := range users {
				if user.GetProxies().GetShadowsocks() == nil {
					continue
				}
				if slices.Contains(user.Inbounds, i.Tag) {
					i.clients[user.GetEmail()] = api.NewShadowsocksTcpAccount(user)
				}
			}
		}
	}
}

func (i *Inbound) updateUser(account api.Account) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.clients == nil {
		i.clients = make(map[string]api.Account)
	}

	email := account.GetEmail()
	switch a := account.(type) {
	case *api.VmessAccount:
		i.clients[email] = a

	case *api.VlessAccount:
		newAccount := checkVless(i, *a)
		i.clients[email] = &newAccount

	case *api.TrojanAccount:
		i.clients[email] = a

	case *api.ShadowsocksTcpAccount:
		i.clients[email] = a

	case *api.ShadowsocksAccount:
		method, ok := i.Settings["method"].(string)
		if ok {
			na := checkShadowsocks2022(method, *a)
			i.clients[email] = &na
		} else {
			i.clients[email] = a
		}
	}
}

func (i *Inbound) updateUsers(accounts []api.Account) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.clients == nil {
		i.clients = make(map[string]api.Account)
	}

	switch i.Protocol {
	case Vmess:
		for _, account := range accounts {
			if a, ok := account.(*api.VmessAccount); ok {
				i.clients[account.GetEmail()] = a
			}
		}

	case Vless:
		for _, account := range accounts {
			if a, ok := account.(*api.VlessAccount); ok {
				newAccount := checkVless(i, *a)
				i.clients[account.GetEmail()] = &newAccount
			}
		}

	case Trojan:
		for _, account := range accounts {
			if a, ok := account.(*api.TrojanAccount); ok {
				i.clients[account.GetEmail()] = a
			}
		}

	case Shadowsocks:
		method, methodOk := i.Settings["method"].(string)
		if methodOk && strings.HasPrefix(method, "2022-blake3") {
			for _, account := range accounts {
				if a, ok := account.(*api.ShadowsocksAccount); ok {
					newAccount := checkShadowsocks2022(method, *a)
					i.clients[account.GetEmail()] = &newAccount
				}
			}
		} else {
			for _, account := range accounts {
				if a, ok := account.(*api.ShadowsocksTcpAccount); ok {
					i.clients[account.GetEmail()] = a
				}
			}
		}
	}
}

func (i *Inbound) removeUser(email string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.clients != nil {
		delete(i.clients, email)
	}
}

type Stats struct{}

func (c *Config) ToBytes() ([]byte, error) {
	// Acquire read locks for all inbounds
	for _, i := range c.InboundConfigs {
		i.mu.RLock()
	}

	// Build slices from maps for serialization
	for _, i := range c.InboundConfigs {
		if i.exclude || i.clients == nil || len(i.clients) == 0 {
			i.Settings["clients"] = []interface{}{}
			continue
		}

		switch i.Protocol {
		case Vmess:
			clients := make([]*api.VmessAccount, 0, len(i.clients))
			for _, account := range i.clients {
				if vmessAccount, ok := account.(*api.VmessAccount); ok {
					clients = append(clients, vmessAccount)
				}
			}
			i.Settings["clients"] = clients

		case Vless:
			clients := make([]*api.VlessAccount, 0, len(i.clients))
			for _, account := range i.clients {
				if vlessAccount, ok := account.(*api.VlessAccount); ok {
					clients = append(clients, vlessAccount)
				}
			}
			i.Settings["clients"] = clients

		case Trojan:
			clients := make([]*api.TrojanAccount, 0, len(i.clients))
			for _, account := range i.clients {
				if trojanAccount, ok := account.(*api.TrojanAccount); ok {
					clients = append(clients, trojanAccount)
				}
			}
			i.Settings["clients"] = clients

		case Shadowsocks:
			method, methodOk := i.Settings["method"].(string)
			if methodOk && strings.HasPrefix(method, "2022-blake3") {
				clients := make([]*api.ShadowsocksAccount, 0, len(i.clients))
				for _, account := range i.clients {
					if ssAccount, ok := account.(*api.ShadowsocksAccount); ok {
						clients = append(clients, ssAccount)
					}
				}
				i.Settings["clients"] = clients
			} else {
				clients := make([]*api.ShadowsocksTcpAccount, 0, len(i.clients))
				for _, account := range i.clients {
					if ssTcpAccount, ok := account.(*api.ShadowsocksTcpAccount); ok {
						clients = append(clients, ssTcpAccount)
					}
				}
				i.Settings["clients"] = clients
			}
		}
	}

	b, err := json.Marshal(c)

	// Release all locks
	for _, i := range c.InboundConfigs {
		i.mu.RUnlock()
	}

	if err != nil {
		return nil, err
	}
	return b, nil
}

func filterRules(rules []json.RawMessage, apiTag string) ([]json.RawMessage, error) {
	if rules == nil {
		rules = []json.RawMessage{}
	}

	filtered := make([]json.RawMessage, 0, len(rules))
	for _, raw := range rules {
		var obj map[string]interface{}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("invalid JSON in rule: %w", err)
		}

		// Check if outboundTag exists and matches apiTag
		if outboundTagValue, ok := obj["outboundTag"].(string); ok && outboundTagValue == apiTag {
			continue
		}

		filtered = append(filtered, raw)
	}

	return filtered, nil
}

func (c *Config) ApplyAPI(apiPort int) (err error) {
	// Remove the existing inbound with the API_INBOUND tag
	for i, inbound := range c.InboundConfigs {
		if inbound.Tag == "API_INBOUND" {
			c.InboundConfigs = append(c.InboundConfigs[:i], c.InboundConfigs[i+1:]...)
		}
	}

	apiTag := "API"

	c.API = &conf.APIConfig{
		Services: []string{"HandlerService", "LoggerService", "StatsService"},
		Tag:      apiTag,
	}

	if c.RouterConfig == nil {
		c.RouterConfig = &conf.RouterConfig{}
	}

	rules := c.RouterConfig.RuleList
	c.RouterConfig.RuleList, err = filterRules(rules, apiTag)

	c.checkPolicy()

	inbound := &Inbound{
		Listen:   "127.0.0.1",
		Port:     apiPort,
		Protocol: "dokodemo-door",
		Settings: map[string]interface{}{"address": "127.0.0.1"},
		Tag:      "API_INBOUND",
		clients:  make(map[string]api.Account),
	}

	c.InboundConfigs = append([]*Inbound{inbound}, c.InboundConfigs...)

	rule := map[string]interface{}{
		"inboundTag":  []string{"API_INBOUND"},
		"source":      []string{"127.0.0.1"},
		"outboundTag": "API",
		"type":        "field",
	}

	rawBytes, err := json.Marshal(rule)
	if err != nil {
		return err
	}

	newRaw := json.RawMessage(rawBytes)

	c.RouterConfig.RuleList = append([]json.RawMessage{newRaw}, c.RouterConfig.RuleList...)

	return nil
}

func (c *Config) checkPolicy() {
	if c.Policy == nil {
		c.Policy = &conf.PolicyConfig{Levels: make(map[uint32]*conf.Policy)}
		c.Policy.Levels[0] = &conf.Policy{StatsUserUplink: true, StatsUserDownlink: true}
		// StatsUserOnline is not set, which will default to false
	} else {
		if c.Policy.Levels == nil {
			c.Policy.Levels = make(map[uint32]*conf.Policy)
		}

		zero, ok := c.Policy.Levels[0]
		if !ok {
			c.Policy.Levels[0] = &conf.Policy{StatsUserUplink: true, StatsUserDownlink: true}
		} else {
			zero.StatsUserDownlink = true
			zero.StatsUserUplink = true
			// Don't modify StatsUserOnline, respect the value that's already there
		}
	}

	if c.Policy.System == nil {
		c.Policy.System = &conf.SystemPolicy{
			StatsInboundDownlink:  false,
			StatsInboundUplink:    false,
			StatsOutboundDownlink: true,
			StatsOutboundUplink:   true,
		}
	} else {
		c.Policy.System.StatsOutboundDownlink = true
		c.Policy.System.StatsOutboundUplink = true
	}
}

func (c *Config) RemoveLogFiles() (accessFile, errorFile string) {
	accessFile = c.LogConfig.AccessLog
	c.LogConfig.AccessLog = ""
	errorFile = c.LogConfig.ErrorLog
	c.LogConfig.ErrorLog = ""

	return accessFile, errorFile
}

func NewXRayConfig(config string, exclude []string) (*Config, error) {
	var xrayConfig Config
	err := json.Unmarshal([]byte(config), &xrayConfig)
	if err != nil {
		return nil, err
	}

	for _, i := range xrayConfig.InboundConfigs {
		if i.clients == nil {
			i.clients = make(map[string]api.Account)
		}
		if slices.Contains(exclude, i.Tag) {
			i.mu.Lock()
			i.exclude = true
			i.mu.Unlock()
		}
	}

	return &xrayConfig, nil
}
