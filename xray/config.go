package xray

import (
	"encoding/json"
	"marzban-node/config"
)

type XRayConfig struct {
	Log       Log           `json:"log,omitempty"`
	Inbounds  []Inbound     `json:"inbounds"`
	Outbounds []interface{} `json:"outbounds,omitempty"`
	Routing   Routing       `json:"routing,omitempty"`
	API       API           `json:"api"`
	Stats     Stats         `json:"stats"`
	Policy    Policy        `json:"policy"`
}

type Log struct {
	Access   string `json:"access,omitempty"`
	Error    string `json:"error,omitempty"`
	LogLevel string `json:"logLevel,omitempty"`
	DnsLog   string `json:"dnsLog,omitempty"`
}

type Inbound struct {
	Listen         string      `json:"listen"`
	Port           int         `json:"port"`
	Protocol       string      `json:"protocol"`
	Settings       interface{} `json:"settings"`
	StreamSettings interface{} `json:"streamSettings"`
	Tag            string      `json:"tag"`
	Sniffing       interface{} `json:"sniffing"`
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
	StatsUserUplink   bool `json:"statsUserUplink"`
	StatsUserDownlink bool `json:"statsUserDownlink"`
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

func NewXRayConfig(config string, peerIP string) (*XRayConfig, error) {
	var xrayConfig XRayConfig
	err := json.Unmarshal([]byte(config), &xrayConfig)
	if err != nil {
		return nil, err
	}

	// Apply API changes
	xrayConfig.applyAPI(peerIP)

	return &xrayConfig, nil
}

func (x *XRayConfig) ToJSON() (string, error) {
	b, err := json.Marshal(x)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (x *XRayConfig) applyAPI(peerIP string) {
	for i, inbound := range x.Inbounds {
		if inbound.Protocol == "dokodemo-door" {
			x.Inbounds = append(x.Inbounds[:i], x.Inbounds[i+1:]...)
			break
		}
	}

	apiTag := x.API.Tag
	for i, rule := range x.Routing.Rules {
		if apiTag != "" && rule.OutboundTag == apiTag {
			x.Routing.Rules = append(x.Routing.Rules[:i], x.Routing.Rules[i+1:]...)
			break
		}
	}

	x.API.Services = []string{"HandlerService", "StatsService", "LoggerService"}
	x.API.Tag = "API"

	x.Stats = Stats{}

	x.Policy = Policy{
		Levels: Levels{
			Zero: Level{
				StatsUserUplink:   true,
				StatsUserDownlink: true,
			},
		},
		System: System{
			StatsInboundDownlink:  false,
			StatsInboundUplink:    false,
			StatsOutboundDownlink: true,
			StatsOutboundUplink:   true,
		},
	}

	inbound := Inbound{
		Listen:   "0.0.0.0",
		Port:     config.XrayApiPort,
		Protocol: "dokodemo-door",
		Settings: Settings{
			Address: "127.0.0.1",
		},
		StreamSettings: StreamSettings{
			Security: "tls",
			TLSSettings: TLSSettings{
				Certificates: []Certificate{
					{
						CertificateFile: config.SslCertFile,
						KeyFile:         config.SslKeyFile,
					},
				},
			},
		},
		Tag: "API_INBOUND",
	}
	x.Inbounds = append([]Inbound{inbound}, x.Inbounds...)

	rule := Rule{
		InboundTag:  []string{"API_INBOUND"},
		Source:      []string{"127.0.0.1", peerIP},
		OutboundTag: "API",
		Type:        "field",
	}
	x.Routing.Rules = append([]Rule{rule}, x.Routing.Rules...)
}
