package xray

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"sort"
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
	Hysteria    = "hysteria"
)

type Config struct {
	LogConfig        *conf.LogConfig    `json:"log"`
	RouterConfig     *conf.RouterConfig `json:"routing"`
	DNSConfig        map[string]any     `json:"dns"`
	InboundConfigs   []*Inbound         `json:"inbounds"`
	OutboundConfigs  any                `json:"outbounds"`
	Policy           *conf.PolicyConfig `json:"policy"`
	API              *conf.APIConfig    `json:"api"`
	Metrics          map[string]any     `json:"metrics,omitempty"`
	Stats            Stats              `json:"stats"`
	Reverse          map[string]any     `json:"reverse,omitempty"`
	FakeDNS          map[string]any     `json:"fakeDns,omitempty"`
	Observatory      map[string]any     `json:"observatory,omitempty"`
	BurstObservatory map[string]any     `json:"burstObservatory,omitempty"`
}

type Inbound struct {
	Tag            string         `json:"tag"`
	Listen         string         `json:"listen,omitempty"`
	Port           any            `json:"port,omitempty"`
	Protocol       string         `json:"protocol"`
	Settings       map[string]any `json:"settings"`
	StreamSettings map[string]any `json:"streamSettings,omitempty"`
	Sniffing       any            `json:"sniffing,omitempty"`
	Allocation     map[string]any `json:"allocate,omitempty"`
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

type inboundUpdate struct {
	accounts       []api.Account
	removeEmailSet map[string]struct{}
}

func (c *Config) buildInboundUpdates(users []*common.User) (map[string]*Inbound, map[string]*inboundUpdate) {
	inboundByTag := make(map[string]*Inbound)
	for _, inbound := range c.InboundConfigs {
		if inbound.exclude {
			continue
		}
		inboundByTag[inbound.Tag] = inbound
	}

	updates := make(map[string]*inboundUpdate, len(inboundByTag))
	for tag := range inboundByTag {
		updates[tag] = &inboundUpdate{
			removeEmailSet: make(map[string]struct{}),
		}
	}

	for _, user := range users {
		settings, _ := setupUserAccount(user)
		userInbounds := user.GetInbounds()
		userEmail := user.GetEmail()

		for tag, inbound := range inboundByTag {
			account, isActive := isActiveInbound(inbound, userInbounds, settings)
			update := updates[tag]
			if isActive {
				update.accounts = append(update.accounts, account)
			} else {
				update.removeEmailSet[userEmail] = struct{}{}
			}
		}
	}

	return inboundByTag, updates
}

func (c *Config) updateUsers(users []*common.User) {
	inboundByTag, updates := c.buildInboundUpdates(users)
	for tag, inbound := range inboundByTag {
		update := updates[tag]
		removeEmails := make([]string, 0, len(update.removeEmailSet))
		for email := range update.removeEmailSet {
			removeEmails = append(removeEmails, email)
		}
		inbound.updateUsers(update.accounts, removeEmails)
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
				i.clients[user.GetEmail()] = account
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

	case Hysteria:
		for _, user := range users {
			if user.GetProxies().GetHysteria() == nil {
				continue
			}
			if slices.Contains(user.Inbounds, i.Tag) {
				i.clients[user.GetEmail()] = api.NewHysteriaAccount(user)
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
		i.clients[email] = a

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

	case *api.HysteriaAccount:
		i.clients[email] = a
	}
}

func (i *Inbound) updateUsers(accounts []api.Account, removeEmails []string) {
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
				i.clients[account.GetEmail()] = a
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

	case Hysteria:
		for _, account := range accounts {
			if a, ok := account.(*api.HysteriaAccount); ok {
				i.clients[account.GetEmail()] = a
			}
		}
	}

	for _, email := range removeEmails {
		delete(i.clients, email)
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
		if i.exclude {
			continue
		}

		if i.Settings == nil {
			i.Settings = make(map[string]any)
		}

		if len(i.clients) == 0 {
			i.Settings["clients"] = []any{}
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

		case Hysteria:
			clients := make([]*api.HysteriaAccount, 0, len(i.clients))
			for _, account := range i.clients {
				if hyAccount, ok := account.(*api.HysteriaAccount); ok {
					clients = append(clients, hyAccount)
				}
			}
			i.Settings["clients"] = clients
		}
	}

	// Save Variables for next use
	aLog := c.LogConfig.AccessLog
	eLog := c.LogConfig.ErrorLog
	c.LogConfig.AccessLog = ""
	c.LogConfig.ErrorLog = ""

	b, err := json.Marshal(c)

	// Restore variables to prevent conflict on next run
	c.LogConfig.AccessLog = aLog
	c.LogConfig.ErrorLog = eLog

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
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("invalid JSON in rule: %w", err)
		}

		// Check if outboundTag exists and matches apiTag
		if outboundTagValue, ok := obj["outboundTag"].(string); ok && outboundTagValue == apiTag {
			continue
		}
		if ruleTagValue, ok := obj["ruleTag"].(string); ok && ruleTagValue == malformedDomainGuardRuleTag {
			continue
		}

		filtered = append(filtered, raw)
	}

	return filtered, nil
}

var privateCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

func replaceGeoIPPrivate(values any) (any, bool) {
	list, ok := values.([]any)
	if !ok {
		return values, false
	}

	updated := make([]any, 0, len(list)+len(privateCIDRs))
	changed := false
	for _, entry := range list {
		s, strOK := entry.(string)
		if strOK && strings.EqualFold(s, "geoip:private") {
			for _, cidr := range privateCIDRs {
				updated = append(updated, cidr)
			}
			changed = true
			continue
		}
		updated = append(updated, entry)
	}

	if !changed {
		return values, false
	}

	return updated, true
}

func normalizeGeoIPPrivateRules(rules []json.RawMessage) ([]json.RawMessage, error) {
	if rules == nil {
		return []json.RawMessage{}, nil
	}

	normalized := make([]json.RawMessage, 0, len(rules))
	for _, raw := range rules {
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("invalid JSON in rule: %w", err)
		}

		ruleChanged := false
		if ip, ok := obj["ip"]; ok {
			newIP, changed := replaceGeoIPPrivate(ip)
			if changed {
				obj["ip"] = newIP
				ruleChanged = true
			}
		}

		if source, ok := obj["source"]; ok {
			newSource, changed := replaceGeoIPPrivate(source)
			if changed {
				obj["source"] = newSource
				ruleChanged = true
			}
		}

		if !ruleChanged {
			normalized = append(normalized, raw)
			continue
		}

		rawBytes, err := json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal normalized rule: %w", err)
		}
		normalized = append(normalized, json.RawMessage(rawBytes))
	}

	return normalized, nil
}

func apiRuleSources() []string {
	seen := map[string]struct{}{
		"127.0.0.1": {},
		"::1":       {},
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{"127.0.0.1", "::1"}
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			if ip == nil || ip.IsUnspecified() {
				continue
			}

			seen[ip.String()] = struct{}{}
		}
	}

	sources := make([]string, 0, len(seen))
	for source := range seen {
		sources = append(sources, source)
	}
	sort.Strings(sources)

	return sources
}

func loopbackListenAddress(port int) string {
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	return addr.String()
}

func (c *Config) outboundProtocolByTag() map[string]string {
	rawOutbounds, ok := c.OutboundConfigs.([]any)
	if !ok {
		return nil
	}

	out := make(map[string]string, len(rawOutbounds))
	for _, outbound := range rawOutbounds {
		obj, ok := outbound.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := obj["tag"].(string)
		protocol, _ := obj["protocol"].(string)
		tag = strings.TrimSpace(tag)
		protocol = strings.TrimSpace(protocol)
		if tag == "" || protocol == "" {
			continue
		}
		out[tag] = protocol
	}

	return out
}

const malformedDomainGuardRuleTag = "PG_NODE_MALFORMED_DOMAIN_GUARD"

func (c *Config) blackholeOutboundTag() string {
	protocolByTag := c.outboundProtocolByTag()
	if len(protocolByTag) == 0 {
		return ""
	}

	tags := make([]string, 0, len(protocolByTag))
	for tag := range protocolByTag {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	for _, tag := range tags {
		if strings.EqualFold(protocolByTag[tag], "blackhole") {
			return tag
		}
	}

	return ""
}

func malformedDomainGuardRule(outboundTag string) (json.RawMessage, error) {
	rule := map[string]any{
		"domain": []string{
			"regexp:^.{254,}$",
			"regexp:(^|\\.)[^.]{64,}(\\.|$)",
		},
		"outboundTag": outboundTag,
		"ruleTag":     malformedDomainGuardRuleTag,
		"type":        "field",
	}

	rawBytes, err := json.Marshal(rule)
	if err != nil {
		return nil, err
	}

	return json.RawMessage(rawBytes), nil
}

var observatoryExcludedProtocols = map[string]struct{}{
	"blackhole": {},
	"dns":       {},
	"loopback":  {},
}

func (c *Config) sanitizeObservatorySelectors() {
	protocolByTag := c.outboundProtocolByTag()
	if len(protocolByTag) == 0 {
		return
	}

	sanitize := func(section map[string]any) {
		if section == nil {
			return
		}
		raw, ok := section["subjectSelector"]
		if !ok {
			return
		}
		values, ok := raw.([]any)
		if !ok {
			return
		}

		filtered := make([]any, 0, len(values))
		for _, value := range values {
			tag, ok := value.(string)
			if !ok {
				continue
			}
			protocol, hasProtocol := protocolByTag[strings.TrimSpace(tag)]
			if hasProtocol {
				if _, excluded := observatoryExcludedProtocols[protocol]; excluded {
					continue
				}
			}
			filtered = append(filtered, tag)
		}
		section["subjectSelector"] = filtered
	}

	sanitize(c.Observatory)
	sanitize(c.BurstObservatory)
}

func (c *Config) ApplyAPI(apiPort, metricPort int) (err error) {
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

	c.Metrics = map[string]any{
		"tag":    "metric",
		"listen": loopbackListenAddress(metricPort),
	}
	c.sanitizeObservatorySelectors()

	if c.RouterConfig == nil {
		c.RouterConfig = &conf.RouterConfig{}
	}

	rules := c.RouterConfig.RuleList
	rules, err = normalizeGeoIPPrivateRules(rules)
	if err != nil {
		return err
	}
	c.RouterConfig.RuleList, err = filterRules(rules, apiTag)
	if err != nil {
		return err
	}

	c.checkPolicy()

	inbound := &Inbound{
		Listen:   "127.0.0.1",
		Port:     apiPort,
		Protocol: "dokodemo-door",
		Settings: map[string]any{"address": "127.0.0.1"},
		Tag:      "API_INBOUND",
		clients:  make(map[string]api.Account),
	}

	c.InboundConfigs = append([]*Inbound{inbound}, c.InboundConfigs...)

	rule := map[string]any{
		"inboundTag":  []string{"API_INBOUND"},
		"source":      apiRuleSources(),
		"outboundTag": "API",
		"type":        "field",
	}

	rawBytes, err := json.Marshal(rule)
	if err != nil {
		return err
	}

	newRaw := json.RawMessage(rawBytes)

	prependRules := []json.RawMessage{newRaw}
	if blockTag := c.blackholeOutboundTag(); blockTag != "" {
		guardRaw, err := malformedDomainGuardRule(blockTag)
		if err != nil {
			return err
		}
		prependRules = append(prependRules, guardRaw)
	}

	c.RouterConfig.RuleList = append(prependRules, c.RouterConfig.RuleList...)

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

func (c *Config) GetLogFiles() (accessFile, errorFile string) {
	if c.LogConfig == nil {
		c.LogConfig = &conf.LogConfig{
			LogLevel: "info",
		}
	}

	return c.LogConfig.AccessLog, c.LogConfig.ErrorLog
}

func NewConfig(config string, exclude []string) (*Config, error) {
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
