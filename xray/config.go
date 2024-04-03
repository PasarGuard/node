package xray

import (
	"encoding/json"
)

type XRayConfig struct {
	Inbounds []Inbound `json:"inbounds"`
	Routing  Routing   `json:"routing"`
	API      API       `json:"api"`
	Stats    Stats     `json:"stats"`
	Policy   Policy    `json:"policy"`
}

type Inbound struct {
	Listen         string         `json:"listen"`
	Port           int            `json:"port"`
	Protocol       string         `json:"protocol"`
	Settings       Settings       `json:"settings"`
	StreamSettings StreamSettings `json:"streamSettings"`
	Tag            string         `json:"tag"`
}

type Settings struct {
	Address string `json:"address"`
}

type StreamSettings struct {
	Security    string      `json:"security"`
	TlsSettings TlsSettings `json:"tlsSettings"`
}

type TlsSettings struct {
	Certificates []Certificate `json:"certificates"`
}

type Certificate struct {
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
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
	InboundTag  []string `json:"inboundTag"`
	Source      []string `json:"source"`
	OutboundTag string   `json:"outboundTag"`
	Type        string   `json:"type"`
}

func NewXRayConfig(config string, peerIP string) (*XRayConfig, error) {
	var xrayConfig XRayConfig
	err := json.Unmarshal([]byte(config), &xrayConfig)
	if err != nil {
		return nil, err
	}

	// Your code here to modify xrayConfig based on peerIP

	return &xrayConfig, nil
}

func (x *XRayConfig) ToJSON() (string, error) {
	b, err := json.Marshal(x)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
