package singbox

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/pasarguard/node/common"
)

// Config wraps an admin-authored sing-box JSON config. Users are injected into
// inbound.users[] at start/sync time (the panel never embeds them), mirroring
// how the xray backend fills inbound.settings.clients.
type Config struct {
	raw      map[string]any
	excluded map[string]bool
}

// NewConfig parses the JSON string and marks excluded inbound tags.
func NewConfig(config string, exclude []string) (*Config, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(config), &raw); err != nil {
		return nil, fmt.Errorf("invalid sing-box config JSON: %w", err)
	}

	excluded := make(map[string]bool, len(exclude))
	for _, tag := range exclude {
		excluded[tag] = true
	}

	c := &Config{raw: raw, excluded: excluded}
	c.normalizeRealityTLS()
	return c, nil
}

// normalizeRealityTLS fills tls.server_name / tls.alpn for Reality inbounds
// that omit them. The panel does the same when it validates a core, but a
// stored config (or one written before that validation existed) reaches the
// node unchanged, and a Reality inbound without the SNI the server
// impersonates fails every client with "reality verification failed".
func (c *Config) normalizeRealityTLS() {
	for _, inbound := range c.inbounds() {
		tls, _ := inbound["tls"].(map[string]any)
		if tls == nil || tls["enabled"] != true {
			continue
		}
		reality, _ := tls["reality"].(map[string]any)
		if reality == nil || reality["enabled"] != true {
			continue
		}
		if name, _ := tls["server_name"].(string); name == "" {
			if handshake, _ := reality["handshake"].(map[string]any); handshake != nil {
				if server, _ := handshake["server"].(string); server != "" {
					tls["server_name"] = server
				}
			}
		}
		if _, ok := tls["alpn"].([]any); !ok {
			tls["alpn"] = []any{"h2", "http/1.1"}
		}
	}
}

// Clone deep-copies the config (used for rollback around failed restarts).
func (c *Config) Clone() *Config {
	buf, err := json.Marshal(c.raw)
	if err != nil {
		// raw came from valid JSON; marshal cannot fail on it
		return &Config{raw: map[string]any{}, excluded: mapsClone(c.excluded)}
	}
	var raw map[string]any
	_ = json.Unmarshal(buf, &raw)
	return &Config{raw: raw, excluded: mapsClone(c.excluded)}
}

func mapsClone(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (c *Config) ToBytes() ([]byte, error) {
	return json.Marshal(c.raw)
}

func (c *Config) inbounds() []map[string]any {
	return toMapSlice(c.raw["inbounds"])
}

func (c *Config) outbounds() []map[string]any {
	return toMapSlice(c.raw["outbounds"])
}

func toMapSlice(v any) []map[string]any {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// ApplyAPI injects experimental.v2ray_api so the node can read per-user traffic
// counters. The listen address must be this node's api port; stats entities are
// enumerated from the config (only listed entities are tracked by sing-box).
// The users list is (re)filled by syncUsers.
func (c *Config) ApplyAPI(apiPort int) error {
	stats := map[string]any{
		"enabled":   true,
		"users":     []any{},
		"inbounds":  tagList(c.inbounds()),
		"outbounds": tagList(c.outbounds()),
	}

	experimental, _ := c.raw["experimental"].(map[string]any)
	if experimental == nil {
		experimental = map[string]any{}
		c.raw["experimental"] = experimental
	}
	experimental["v2ray_api"] = map[string]any{
		"listen": fmt.Sprintf("127.0.0.1:%d", apiPort),
		"stats":  stats,
	}
	// Re-derive from whatever users are already injected: ApplyAPI can be
	// called after syncUsers (e.g. on backend New) and must not wipe the list.
	c.refreshStatsUsers()
	return nil
}

func tagList(inbounds []map[string]any) []any {
	tags := make([]any, 0, len(inbounds))
	for _, in := range inbounds {
		if tag, ok := in["tag"].(string); ok && tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

// syncUsers injects users[] into every non-excluded inbound whose type matches
// a credential the user carries, and refreshes v2ray_api.stats.users.
// users[].name is the identity key (metadata.User -> auth_user + stats keys),
// so it must equal the panel's email (= stringified user id).
func (c *Config) syncUsers(users []*common.User) {
	inbounds := c.inbounds()

	for _, inbound := range inbounds {
		tag, _ := inbound["tag"].(string)
		if tag == "" || c.excluded[tag] {
			continue
		}
		injected := make([]any, 0, len(users))
		for _, user := range users {
			userObj, ok := userEntryFor(inbound, user)
			if !ok {
				continue
			}
			if !slices.Contains(user.GetInbounds(), tag) {
				continue
			}
			injected = append(injected, userObj)
		}
		inbound["users"] = injected
	}

	c.refreshStatsUsers()
	c.refreshQuota(users)
}

// refreshQuota publishes each user's remaining budget into the config.
//
// Budgets belong in the config rather than being pushed over the control
// endpoint after start: the core reads them while constructing the stats
// service, before any listener exists, so a restart cannot open a window in
// which a limited user has no budget. That is the "re-pushed before the
// inbound accepts traffic" guarantee — by construction, not by timing.
//
// A user with no budget is simply absent, which is what unlimited means to the
// core; only users the panel flagged get an entry.
func (c *Config) refreshQuota(users []*common.User) {
	experimental, ok := c.raw["experimental"].(map[string]any)
	if !ok {
		return
	}
	v2api, ok := experimental["v2ray_api"].(map[string]any)
	if !ok {
		return
	}
	stats, ok := v2api["stats"].(map[string]any)
	if !ok {
		return
	}

	budgets := make(map[string]any, len(users))
	for _, user := range users {
		email := user.GetEmail()
		quota := user.GetQuota()
		if email == "" || quota == 0 {
			// 0 means "no budget" on the wire; leaving the user out of the map
			// is the core's notion of unlimited.
			continue
		}
		budgets[email] = int64(quota)
	}

	if len(budgets) == 0 {
		delete(stats, "quota")
		return
	}
	stats["quota"] = map[string]any{"users": budgets}
}

// refreshStatsUsers rewrites experimental.v2ray_api.stats.users from the
// identities currently present in non-excluded inbounds. Only listed users get
// counters, so this must track the injected users[].name set exactly.
func (c *Config) refreshStatsUsers() {
	experimental, ok := c.raw["experimental"].(map[string]any)
	if !ok {
		return
	}
	v2api, ok := experimental["v2ray_api"].(map[string]any)
	if !ok {
		return
	}
	stats, ok := v2api["stats"].(map[string]any)
	if !ok {
		return
	}

	seen := make(map[string]bool)
	names := make([]any, 0, len(c.raw))
	for _, inbound := range c.inbounds() {
		tag, _ := inbound["tag"].(string)
		if tag == "" || c.excluded[tag] {
			continue
		}
		users, _ := inbound["users"].([]any)
		for _, u := range users {
			entry, _ := u.(map[string]any)
			if entry == nil {
				continue
			}
			if name, _ := entry["name"].(string); name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	stats["users"] = names
}

// userEntryFor builds the sing-box users[] element for an inbound from the
// user's credentials. Returns ok=false when the user has no credential for it.
// The inbound map is consulted for admin-authored per-inbound defaults (e.g.
// the vless flow used by Reality cores — the panel has no per-user flow field).
func userEntryFor(inbound map[string]any, user *common.User) (map[string]any, bool) {
	name := user.GetEmail()
	proxies := user.GetProxies()
	if name == "" || proxies == nil {
		return nil, false
	}
	inboundType, _ := inbound["type"].(string)

	switch inboundType {
	case "vless":
		v := proxies.GetVless()
		if v == nil || v.GetId() == "" {
			return nil, false
		}
		entry := map[string]any{"name": name, "uuid": v.GetId()}
		// flow priority: user-level (bridge proto) then the admin-authored
		// inbound template (where Reality cores normally carry it)
		flow := v.GetFlow()
		if flow == "" {
			flow = templateVlessFlow(inbound)
		}
		if flow == "" && inboundEnablesReality(inbound) {
			// Reality inbounds effectively require xtls-rprx-vision: without
			// it clients fail with "reality verification failed" (verified
			// against sing-box 1.14.2). Default it so an admin-authored
			// config needs no per-user flow at all.
			flow = "xtls-rprx-vision"
		}
		if flow != "" {
			entry["flow"] = flow
		}
		return entry, true

	case "vmess":
		v := proxies.GetVmess()
		if v == nil || v.GetId() == "" {
			return nil, false
		}
		return map[string]any{"name": name, "uuid": v.GetId(), "alterId": 0}, true

	case "trojan":
		t := proxies.GetTrojan()
		if t == nil || t.GetPassword() == "" {
			return nil, false
		}
		return map[string]any{"name": name, "password": t.GetPassword()}, true

	case "shadowsocks":
		// Multi-user shadowsocks: sing-box switches to MultiInbound whenever
		// users[] is present (protocol/shadowsocks/inbound.go). For 2022
		// methods the client password must be "serverKey:userKey" (see
		// sing-shadowsocks shadowaead_2022/protocol.go NewWithPassword —
		// it splits on ":"), and the server keeps its own PSK at the inbound
		// top level; for classic methods each user simply carries their own
		// password and the server tries each key. users[].name is the stats
		// identity either way.
		s := proxies.GetShadowsocks()
		if s == nil || s.GetPassword() == "" {
			return nil, false
		}
		return map[string]any{"name": name, "password": s.GetPassword()}, true

	case "shadowtls":
		// shadowtls v3 wraps an inner shadowsocks inbound; the v3 password is
		// that inner SS inbound's own password, not a per-user credential.
		_ = proxies.GetShadowsocks()
		return nil, false

	case "hysteria2":
		h := proxies.GetHysteria()
		if h == nil || h.GetAuth() == "" {
			return nil, false
		}
		return map[string]any{"name": name, "password": h.GetAuth()}, true

	case "tuic":
		// TUIC needs uuid+password; the proto has no tuic credential, so reuse
		// the vless/vmess uuid and hysteria auth (panel sends both when it
		// assigns a user to a tuic inbound).
		h := proxies.GetHysteria()
		uuid := ""
		if v := proxies.GetVless(); v != nil && v.GetId() != "" {
			uuid = v.GetId()
		} else if v := proxies.GetVmess(); v != nil && v.GetId() != "" {
			uuid = v.GetId()
		}
		if uuid == "" || h == nil || h.GetAuth() == "" {
			return nil, false
		}
		return map[string]any{"name": name, "uuid": uuid, "password": h.GetAuth()}, true

	default:
		// unknown inbound type (wireguard endpoints, mixed, http, ...): no injection
		return nil, false
	}
}

// templateVlessFlow reads the flow from the admin-authored users[] template of
// a vless inbound (the panel does not model per-user flow; Reality cores put
// xtls-rprx-vision on the inbound's user entries).
func templateVlessFlow(inbound map[string]any) string {
	users, _ := inbound["users"].([]any)
	for _, u := range users {
		m, _ := u.(map[string]any)
		if m == nil {
			continue
		}
		if flow, _ := m["flow"].(string); flow != "" {
			return flow
		}
	}
	return ""
}

// inboundEnablesReality reports whether the inbound runs a Reality TLS block.
func inboundEnablesReality(inbound map[string]any) bool {
	tls, _ := inbound["tls"].(map[string]any)
	if tls == nil || tls["enabled"] != true {
		return false
	}
	reality, _ := tls["reality"].(map[string]any)
	return reality != nil && reality["enabled"] == true
}
