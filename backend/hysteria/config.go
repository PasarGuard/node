package hysteria

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/pasarguard/node/common"
)

// Hysteria 2 is configured in YAML upstream, but viper reads JSON too and its
// SupportedExts lists yaml first only as a preference
// (app/cmd/root.go:132 `viper.SupportedExts = append([]string{"yaml", "yml"}, ...)`).
// JSON is what the panel authors, what the node already speaks, and what needs
// no new dependency. Verified against v2.13.0 on Windows: a .json server config
// loads and runs.
//
// Config wraps an admin-authored hysteria2 server config. Users are injected
// into auth.userpass at start/sync time (the panel never embeds them), the same
// way the sing-box backend fills inbound.users[] and xray fills
// inbound.settings.clients.
type Config struct {
	raw      map[string]any
	excluded map[string]bool
}

// NewConfig parses the JSON string and marks excluded inbound tags.
func NewConfig(config string, exclude []string) (*Config, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(config), &raw); err != nil {
		return nil, fmt.Errorf("invalid hysteria config JSON: %w", err)
	}

	excluded := make(map[string]bool, len(exclude))
	for _, tag := range exclude {
		excluded[tag] = true
	}

	return &Config{raw: raw, excluded: excluded}, nil
}

// Clone deep-copies the config (used for rollback around a failed restart).
func (c *Config) Clone() *Config {
	buf, err := json.Marshal(c.raw)
	if err != nil {
		// raw came from valid JSON; marshal cannot fail on it.
		return &Config{raw: map[string]any{}, excluded: maps.Clone(c.excluded)}
	}
	var raw map[string]any
	_ = json.Unmarshal(buf, &raw)
	return &Config{raw: raw, excluded: maps.Clone(c.excluded)}
}

func (c *Config) ToBytes() ([]byte, error) {
	return json.MarshalIndent(c.raw, "", "  ")
}

// AuthType reports the configured auth.type, lowercased. "" when unset, which
// upstream treats as `password` with an empty password — i.e. open.
func (c *Config) AuthType() string {
	auth, _ := c.raw["auth"].(map[string]any)
	t, _ := auth["type"].(string)
	return strings.ToLower(t)
}

// Password returns the shared `password` auth secret, or "".
func (c *Config) Password() string {
	auth, _ := c.raw["auth"].(map[string]any)
	p, _ := auth["password"].(string)
	return p
}

// ObfsType reports the configured obfs.type, lowercased, or "".
func (c *Config) ObfsType() string {
	obfs, _ := c.raw["obfs"].(map[string]any)
	t, _ := obfs["type"].(string)
	return strings.ToLower(t)
}

// ObfsPassword returns the salamander/gecko obfs password, or "".
func (c *Config) ObfsPassword() string {
	obfs, _ := c.raw["obfs"].(map[string]any)
	switch t := strings.ToLower(stringAt(obfs, "type")); t {
	case "", "salamander":
		sal, _ := obfs["salamander"].(map[string]any)
		p, _ := sal["password"].(string)
		return p
	case "gecko":
		gecko, _ := obfs["gecko"].(map[string]any)
		p, _ := gecko["password"].(string)
		return p
	default:
		return ""
	}
}

// MasqueradeConfigured reports whether a masquerade target is set. The panel
// decides which of HTTP/HTTPS listeners to render; the node only has to know
// whether one exists.
func (c *Config) MasqueradeConfigured() bool {
	masq, ok := c.raw["masquerade"].(map[string]any)
	if !ok {
		return false
	}
	return stringAt(masq, "type") != ""
}

// Listen returns the configured `listen`, or "". Port-hopping ranges appear
// here verbatim ("0.0.0.0:20000-50000").
func (c *Config) Listen() string {
	s, _ := c.raw["listen"].(string)
	return s
}

func stringAt(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// syncUsers rewrites auth.userpass from the panel's user set.
//
// Auth mode is chosen by the admin-authored `auth.type`:
//
//   - `userpass` is the only mode that gives per-user attribution. Upstream's
//     Authenticate returns the *username* as the id (extras/auth/userpass.go:38
//     `return true, u`), and that id is what the traffic stats API keys on.
//   - `password` returns the fixed id "user" (extras/auth/password.go:21), so
//     every client is billed as one user. It still works; there is just nothing
//     to attribute. The node says so rather than shipping wrong numbers.
//
// A user is injected only when the panel put them on this core: `user.Inbounds`
// carries the tags assigned to them, and an empty list means the panel assigned
// no specific tag (xray treats it as "all inbounds", so this does too).
//
// It returns an error naming every user whose identity the core's decoder
// cannot accept, so the caller can refuse the start with a message an admin can
// act on instead of a core that exits on a config-parse FATAL.
func (c *Config) syncUsers(users []*common.User) error {
	auth, ok := c.raw["auth"].(map[string]any)
	if !ok {
		auth = map[string]any{}
		c.raw["auth"] = auth
	}

	switch c.AuthType() {
	case "password", "http", "command":
		// Nothing to inject: these modes carry their credentials in the config
		// itself. The panel is the only thing that knows a user's status.
		return nil
	}

	var rejected []string
	assigned := make(map[string]any, len(users))
	for _, user := range users {
		username, password, ok := credentialFor(user)
		if !ok {
			continue
		}
		if !assignedToThisCore(user, c.excluded) {
			continue
		}
		if bad := undecodableUsernameChar(username); bad != "" {
			// Collected, not returned on the first one: an admin who fixed these
			// one at a time would need one core restart per user.
			rejected = append(rejected, fmt.Sprintf("%q (character %q)", username, bad))
			continue
		}
		assigned[username] = password
	}
	auth["userpass"] = assigned

	if len(rejected) > 0 {
		slices.Sort(rejected)
		return fmt.Errorf(
			"hysteria cannot use these usernames in auth.userpass: %s. "+
				"Upstream decodes auth.userpass with a path-aware decoder that treats %q as a "+
				"path separator, so a username containing one arrives as a nested map instead of a "+
				"string and the core refuses to start. Every other character is accepted. "+
				"Rename the user, or give this core a numeric identity.",
			strings.Join(rejected, ", "), usernameSeparator,
		)
	}
	return nil
}

// usernameSeparator is the one character upstream's config decoder mishandles
// in a username.
//
// Upstream decodes auth.userpass with a path-aware decoder that splits a key on
// this character, so the key "a.b" arrives as a nested map instead of a string
// and the core exits during startup:
//
//	'auth.userpass[a]' expected type 'string', got unconvertible type 'map[string]interface {}'
//
// Measured against the pinned v2.13.0 binary, not inferred: of every ASCII
// punctuation character plus tab, space, `@`, `:` , `/`, `\`, `[`, `#`, and
// non-ASCII letters, ONLY this one makes the core refuse to start. The value
// side (the password), obfs.salamander/gecko.password, auth.password,
// masquerade content and trafficStats.secret all accept dots freely — only a
// MAP KEY in auth.userpass is affected. So the rule is one character, not a
// character class, and inventing a broader allowlist would reject identities
// upstream accepts.
const usernameSeparator = "."

// undecodableUsernameChar returns the character that makes upstream's decoder
// reject name, or "" when it is fine.
func undecodableUsernameChar(name string) string {
	if i := strings.Index(name, usernameSeparator); i >= 0 {
		return usernameSeparator
	}
	return ""
}

// credentialFor maps a panel user onto a hysteria `userpass` pair.
//
// The username is the user's email — the same identity key the other backends
// use (xray's inbound.settings.clients.email, sing-box's users[].name) — so a
// per-user counter read back from the traffic stats API lands on a row the
// panel already recognises. The password is Hysteria.auth, the field the panel
// already generates per user (app/models/proxy.py HysteriaSettings.auth).
//
// The username is NOT rewritten. It is load-bearing on the client side: a
// hysteria2 client authenticates with "username:password" and upstream rejects
// the connection when the username does not match a key (verified: client
// auth "pw" against userpass {alice: pw} fails with "authentication error, HTTP
// status code: 404"). Encoding the key to make it dot-free would therefore break
// every real client, so the identity is kept and the bad one is refused at start.
func credentialFor(user *common.User) (username, password string, ok bool) {
	email := user.GetEmail()
	proxies := user.GetProxies()
	if email == "" || proxies == nil {
		return "", "", false
	}
	h := proxies.GetHysteria()
	if h == nil || h.GetAuth() == "" {
		return "", "", false
	}
	return email, h.GetAuth(), true
}

// assignedToThisCore reports whether the panel placed this user on one of the
// core's non-excluded inbounds.
func assignedToThisCore(user *common.User, excluded map[string]bool) bool {
	inbounds := user.GetInbounds()
	if len(inbounds) == 0 {
		return true
	}
	for _, tag := range inbounds {
		if !excluded[tag] {
			return true
		}
	}
	return false
}

// userNames returns the usernames currently in auth.userpass.
func (c *Config) userNames() []string {
	auth, _ := c.raw["auth"].(map[string]any)
	up, _ := auth["userpass"].(map[string]any)
	names := make([]string, 0, len(up))
	for name := range up {
		if name != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// EnableTrafficStats points the core's traffic stats API at this core's own
// loopback port and installs the node-generated secret.
//
// The secret lives in the config file, unlike sing-box's quota secret which
// travels in the child's environment. That is not a choice: stock hysteria
// v2.13.0 reads only `trafficStats.secret` from the config and consults no
// environment variable at all (app/cmd/server.go:280-283 is the whole struct).
// The mitigation is the same one upstream intends — the listener is bound to
// 127.0.0.1, never a routable address — plus 0600 on the written file
// (see Core.writeConfigFile). Anyone who can read the file can already read the
// user's passwords out of auth.userpass.
func (c *Config) EnableTrafficStats(apiPort int, secret string) {
	if apiPort <= 0 {
		return
	}
	stats, ok := c.raw["trafficStats"].(map[string]any)
	if !ok {
		stats = map[string]any{}
		c.raw["trafficStats"] = stats
	}
	stats["listen"] = fmt.Sprintf("127.0.0.1:%d", apiPort)
	// Set explicitly even when the caller passes one: an operator-authored
	// secret in a stored config must not become the node's only credential.
	stats["secret"] = secret
}
