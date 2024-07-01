package xray

import (
	"encoding/json"
)

type Protocol string

const (
	Vmess       = "vmess"
	Vless       = "vless"
	Trojan      = "trojan"
	Shadowsocks = "shadowsocks"
)

type Config struct {
	Log       Log           `json:"log,omitempty"`
	Inbounds  []Inbound     `json:"Inbounds"`
	Outbounds []interface{} `json:"outbounds,omitempty"`
	Routing   Routing       `json:"routing,omitempty"`
	API       API           `json:"api"`
	Stats     Stats         `json:"stats"`
	Policy    Policy        `json:"policy"`
}

type Log struct {
	Access   string `json:"access,omitempty"`
	Error    string `json:"error,omitempty"`
	LogLevel string `json:"loglevel,omitempty"`
	DnsLog   string `json:"dnsLog,omitempty"`
}

type Inbound struct {
	Listen         string                 `json:"listen,omitempty"`
	Port           int                    `json:"port,omitempty"`
	Protocol       string                 `json:"protocol"`
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings map[string]interface{} `json:"streamSettings,omitempty"`
	Tag            string                 `json:"tag"`
	Sniffing       interface{}            `json:"sniffing,omitempty"`
}

type API struct {
	Services []string `json:"services"`
	Tag      string   `json:"tag"`
}

type Stats struct{}

type Policy struct {
	Levels Levels `json:"levels"`
	System System `json:"system"`
}

type Levels struct {
	Zero Level `json:"0"`
}

type Level struct {
	Handshake         int  `json:"handshake,omitempty"`
	ConnIdle          int  `json:"connIdle,omitempty"`
	UplinkOnly        int  `json:"uplinkOnly,omitempty"`
	DownlinkOnly      int  `json:"downlinkOnly,omitempty"`
	StatsUserUplink   bool `json:"statsUserUplink"`
	StatsUserDownlink bool `json:"statsUserDownlink"`
	BufferSize        int  `json:"bufferSize,omitempty"`
}

type System struct {
	StatsInboundDownlink  bool `json:"statsInboundDownlink"`
	StatsInboundUplink    bool `json:"statsInboundUplink"`
	StatsOutboundDownlink bool `json:"statsOutboundDownlink"`
	StatsOutboundUplink   bool `json:"statsOutboundUplink"`
}

type Routing struct {
	Rules []Rule `json:"rules"`
}

type Rule struct {
	DomainMatcher string            `json:"domainMatcher,omitempty"`
	Type          string            `json:"type,omitempty"`
	Domain        []string          `json:"domain,omitempty"`
	IP            []string          `json:"ip,omitempty"`
	Port          string            `json:"port,omitempty"`
	SourcePort    string            `json:"sourcePort,omitempty"`
	Network       string            `json:"network,omitempty"`
	Source        []string          `json:"source,omitempty"`
	User          []string          `json:"user,omitempty"`
	InboundTag    []string          `json:"inboundTag,omitempty"`
	Protocol      []string          `json:"protocol,omitempty"`
	Attrs         map[string]string `json:"attrs,omitempty"`
	OutboundTag   string            `json:"outboundTag,omitempty"`
	BalancerTag   string            `json:"balancerTag,omitempty"`
}

type Settings struct {
	Address string `json:"address"`
}

type StreamSettings struct {
	Security    string      `json:"security"`
	TLSSettings TLSSettings `json:"tlsSettings"`
}

type TLSSettings struct {
	Certificates []Certificate `json:"certificates"`
}

type Certificate struct {
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
}

func (c *Config) ToJSON() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func NewXRayConfig(config string) (*Config, error) {
	var xrayConfig Config
	err := json.Unmarshal([]byte(config), &xrayConfig)
	if err != nil {
		return nil, err
	}

	return &xrayConfig, nil
}

func (c *Config) ApplyAPI(apiPort int) error {
	for i, inbound := range c.Inbounds {
		if inbound.Protocol == "dokodemo-door" {
			c.Inbounds = append(c.Inbounds[:i], c.Inbounds[i+1:]...)
		}
	}

	apiTag := c.API.Tag
	for i, rule := range c.Routing.Rules {
		if apiTag != "" && rule.OutboundTag == apiTag {
			c.Routing.Rules = append(c.Routing.Rules[:i], c.Routing.Rules[i+1:]...)
		}
	}

	c.API.Services = []string{"HandlerService", "LoggerService", "StatsService"}
	c.API.Tag = "API"

	c.Stats = Stats{}

	c.checkPolicy()

	inbound := Inbound{
		Listen:   "127.0.0.1",
		Port:     apiPort,
		Protocol: "dokodemo-door",
		Settings: map[string]interface{}{
			"address": "127.0.0.1",
		},
		//StreamSettings: map[string]interface{}{
		//	"security": "tls",
		//	"tlsSettings": map[string]interface{}{
		//		"certificates": []map[string]string{
		//			{
		//				"certificateFile": cert,
		//				"keyFile":         key,
		//			},
		//		},
		//	},
		//},
		Tag: "API_INBOUND",
	}
	c.Inbounds = append([]Inbound{inbound}, c.Inbounds...)

	rule := Rule{
		InboundTag:  []string{"API_INBOUND"},
		Source:      []string{"127.0.0.1"},
		OutboundTag: "API",
		Type:        "field",
	}
	c.Routing.Rules = append([]Rule{rule}, c.Routing.Rules...)
	return nil
}

func (c *Config) checkPolicy() {
	c.Policy.Levels.Zero.StatsUserDownlink = true
	c.Policy.Levels.Zero.StatsUserUplink = true

	c.Policy.System = System{
		StatsInboundDownlink:  false,
		StatsInboundUplink:    false,
		StatsOutboundDownlink: true,
		StatsOutboundUplink:   true,
	}
}
