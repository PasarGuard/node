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

// statsBlock returns the v2ray_api stats block, creating any missing level.
//
// Every writer in this file goes through here on purpose. Each of them
// previously repeated the "walk experimental -> v2ray_api -> stats" lookup, and
// one of them (ApplyAPI) replaced the whole stats block and silently dropped
// quota.listen with it — the core then ran with budgets but no way to update
// them. Routing every write through one accessor, and keeping the quota block,
// makes that class of bug a single place to check.
func (c *Config) statsBlock() map[string]any {
	experimental, ok := c.raw["experimental"].(map[string]any)
	if !ok {
		experimental = map[string]any{}
		c.raw["experimental"] = experimental
	}
	v2api, ok := experimental["v2ray_api"].(map[string]any)
	if !ok {
		v2api = map[string]any{}
		experimental["v2ray_api"] = v2api
	}
	stats, ok := v2api["stats"].(map[string]any)
	if !ok {
		stats = map[string]any{}
		v2api["stats"] = stats
	}
	return stats
}

// quotaBudgets reads the budgets currently written into the config. Read-only,
// for diagnostics and tests.
func (c *Config) quotaBudgets() map[string]int64 {
	experimental, ok := c.raw["experimental"].(map[string]any)
	if !ok {
		return nil
	}
	v2api, ok := experimental["v2ray_api"].(map[string]any)
	if !ok {
		return nil
	}
	stats, ok := v2api["stats"].(map[string]any)
	if !ok {
		return nil
	}
	quota, ok := stats["quota"].(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := quota["users"].(map[string]any)
	if !ok {
		return nil
	}
	budgets := make(map[string]int64, len(raw))
	for user, value := range raw {
		switch typed := value.(type) {
		case int64:
			budgets[user] = typed
		case float64:
			budgets[user] = int64(typed)
		}
	}
	return budgets
}

// preserveQuota carries quota across a rebuild of the stats block. Returns true
// when there was one, so callers can report a dropped budget instead of losing
// it quietly.
func (c *Config) preserveQuota(stats map[string]any) bool {
	previous, ok := c.raw["experimental"].(map[string]any)
	if !ok {
		return false
	}
	v2api, ok := previous["v2ray_api"].(map[string]any)
	if !ok {
		return false
	}
	old, ok := v2api["stats"].(map[string]any)
	if !ok {
		return false
	}
	quota, has := old["quota"]
	if !has {
		return false
	}
	stats["quota"] = quota
	return true
}

// ApplyAPI injects experimental.v2ray_api so the node can read per-user traffic
// counters. The listen address must be this node's api port; stats entities are
// enumerated from the config (only listed entities are tracked by sing-box).
// The users list is (re)filled by syncUsers.
func (c *Config) ApplyAPI(apiPort int) error {
	stats := c.statsBlock()
	stats["enabled"] = true
	stats["users"] = []any{}
	stats["inbounds"] = tagList(c.inbounds())
	stats["outbounds"] = tagList(c.outbounds())

	// ApplyAPI replaces the stats block wholesale, so anything the caller set
	// up beforehand — notably the quota endpoint's listen address — has to be
	// carried across or it is silently dropped. Losing it means the core starts
	// with budgets but no way to update them, which looks like "enforcement
	// works" right up until a limit change has no effect.
	c.preserveQuota(stats)

	experimental, _ := c.raw["experimental"].(map[string]any)
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

// resetQuotas zeroes every budget the core knows about, without touching
// anything else in the config.
//
// This is the fail-closed switch for KNOWN-ISSUES #15. A core the node brings
// back by itself (checkSingBoxHealth after a crash) is restarted from the last
// config it had, and that config carries "remaining at the last panel sync" —
// which the crashed core had already spent. Reusing it would hand the user a
// second budget for the same traffic. Zeroing instead means nobody moves a
// byte until the panel re-syncs with a freshly computed remaining.
//
// Note the two meanings of zero, which is deliberate and must not be
// "cleaned up": a zero in the *proto* means the panel has no budget for this
// user (unlimited) and the node omits them from the config entirely; a zero
// *in the config* means spend nothing. refreshQuota maps the first to absent,
// this writes the second directly.
func (c *Config) resetQuotas() int {
	experimental, ok := c.raw["experimental"].(map[string]any)
	if !ok {
		return 0
	}
	v2api, ok := experimental["v2ray_api"].(map[string]any)
	if !ok {
		return 0
	}
	stats, ok := v2api["stats"].(map[string]any)
	if !ok {
		return 0
	}

	// Everyone the core could possibly authenticate, whether or not the panel
	// gave them a budget. Reading only stats.users would miss any user the
	// stats list failed to pick up, and an unlimited user moving freely in the
	// window before the panel re-syncs is the unsafe outcome here.
	names := map[string]bool{}
	if listed, ok := stats["users"].([]any); ok {
		for _, name := range listed {
			if user, ok := name.(string); ok && user != "" {
				names[user] = true
			}
		}
	}
	for _, inbound := range c.inbounds() {
		if tag, _ := inbound["tag"].(string); tag == "" || c.excluded[tag] {
			continue
		}
		users, _ := inbound["users"].([]any)
		for _, entry := range users {
			obj, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if name, _ := obj["name"].(string); name != "" {
				names[name] = true
			}
		}
	}
	if len(names) == 0 {
		return 0
	}

	budgets := make(map[string]any, len(names))
	for user := range names {
		budgets[user] = int64(0)
	}
	// Preserve `listen` for the same reason refreshQuota does.
	quota, ok := stats["quota"].(map[string]any)
	if !ok {
		quota = map[string]any{}
		stats["quota"] = quota
	}
	quota["users"] = budgets
	return len(budgets)
}

// EnableQuotaEndpoint turns on the core's loopback control endpoint, which the
// node uses to update budgets on a running core instead of restarting it, and
// to detect that a budget has run out.
//
// The secret argument is deliberately written as "" into the config: the value
// itself travels to the child process through its environment (see Core.Start),
// because the config file is copied into images and crash dumps. The core reads
// SINGBOX_QUOTA_SECRET and ignores this field when that is set.
func (c *Config) EnableQuotaEndpoint(port int, _ string) {
	if port <= 0 {
		return
	}
	experimental, ok := c.raw["experimental"].(map[string]any)
	if !ok {
		experimental = map[string]any{}
		c.raw["experimental"] = experimental
	}
	v2api, ok := experimental["v2ray_api"].(map[string]any)
	if !ok {
		v2api = map[string]any{}
		experimental["v2ray_api"] = v2api
	}
	stats, ok := v2api["stats"].(map[string]any)
	if !ok {
		stats = map[string]any{}
		v2api["stats"] = stats
	}
	quota, ok := stats["quota"].(map[string]any)
	if !ok {
		quota = map[string]any{}
		stats["quota"] = quota
	}
	quota["listen"] = fmt.Sprintf("127.0.0.1:%d", port)
}

// quotaEndpoint reports the core's control endpoint address, or "" when the
// endpoint is not enabled. Read off the config because that is where it comes
// from: the panel authors the config, the node does not own this setting.
func (c *Config) quotaEndpoint() string {
	// Read-only: this must not create a stats block that was never there.
	experimental, ok := c.raw["experimental"].(map[string]any)
	if !ok {
		return ""
	}
	v2api, ok := experimental["v2ray_api"].(map[string]any)
	if !ok {
		return ""
	}
	stats, ok := v2api["stats"].(map[string]any)
	if !ok {
		return ""
	}
	quota, ok := stats["quota"].(map[string]any)
	if !ok {
		return ""
	}
	listen, _ := quota["listen"].(string)
	return listen
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

	// Rewrite only the budgets. Replacing the whole block would drop the
	// endpoint's `listen`, so the core would silently come up with no control
	// endpoint — the budgets would still be in the config, but nothing could
	// update them on a running core.
	quota, ok := stats["quota"].(map[string]any)
	if !ok {
		quota = map[string]any{}
		stats["quota"] = quota
	}
	if len(budgets) == 0 {
		delete(quota, "users")
		return
	}
	quota["users"] = budgets
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
