package xray

import (
	"encoding/json"

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
	RouterConfig     map[string]interface{} `json:"routing"`
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
}

type Stats struct{}

func (c *Config) ToJSON() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *Config) ApplyAPI(apiPort int) error {
	// Remove the existing inbound with the API_INBOUND tag
	for i, inbound := range c.InboundConfigs {
		if inbound.Tag == "API_INBOUND" {
			c.InboundConfigs = append(c.InboundConfigs[:i], c.InboundConfigs[i+1:]...)
		}
	}

	if c.API == nil {
		c.API = &conf.APIConfig{
			Services: []string{"HandlerService", "LoggerService", "StatsService"},
			Tag:      "API",
		}
	}

	rules, ok := c.RouterConfig["rules"].([]map[string]interface{})
	if c.API.Tag != "" {
		apiTag := c.API.Tag
		if ok {
			for i, rule := range rules {
				if outboundTag, ok := rule["outboundTag"].(string); ok && outboundTag == apiTag {
					rules = append(rules[:i], rules[i+1:]...)
				}
			}
		} else {
			// Initialize RouterConfig if it's nil
			if c.RouterConfig == nil {
				c.RouterConfig = make(map[string]interface{})
			}
			// Set a default empty slice of rules
			c.RouterConfig["rules"] = []map[string]interface{}{}
		}
	}

	c.checkPolicy()

	inbound := &Inbound{
		Listen:   "127.0.0.1",
		Port:     apiPort,
		Protocol: "dokodemo-door",
		Settings: map[string]interface{}{"address": "127.0.0.1"},
		Tag:      "API_INBOUND",
	}

	c.InboundConfigs = append([]*Inbound{inbound}, c.InboundConfigs...)

	rule := map[string]interface{}{
		"inboundTag":  []string{"API_INBOUND"},
		"source":      []string{"127.0.0.1"},
		"outboundTag": "API",
		"type":        "field",
	}

	c.RouterConfig["rules"] = append([]map[string]interface{}{rule}, rules...)

	return nil
}

func (c *Config) checkPolicy() {
	if c.Policy != nil {
		zero, ok := c.Policy.Levels[0]
		if !ok {
			c.Policy.Levels[0] = &conf.Policy{StatsUserUplink: true, StatsUserDownlink: true}
		} else {
			zero.StatsUserDownlink = true
			zero.StatsUserUplink = true
		}
	} else {
		c.Policy = &conf.PolicyConfig{Levels: make(map[uint32]*conf.Policy)}
		c.Policy.Levels[0] = &conf.Policy{StatsUserUplink: true, StatsUserDownlink: true}
	}

	c.Policy.System = &conf.SystemPolicy{
		StatsInboundDownlink:  false,
		StatsInboundUplink:    false,
		StatsOutboundDownlink: true,
		StatsOutboundUplink:   true,
	}
}

func (c *Config) RemoveLogFiles() (accessFile, errorFile string) {
	accessFile = c.LogConfig.AccessLog
	c.LogConfig.AccessLog = ""
	errorFile = c.LogConfig.ErrorLog
	c.LogConfig.ErrorLog = ""

	return accessFile, errorFile
}

func NewXRayConfig(config string) (*Config, error) {
	var xrayConfig Config
	err := json.Unmarshal([]byte(config), &xrayConfig)
	if err != nil {
		return nil, err
	}

	return &xrayConfig, nil
}
