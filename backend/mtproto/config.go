package mtproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/pasarguard/node/common"
)

const (
	defaultInboundTag = "mtproto"
	loopbackV4CIDR    = "127.0.0.1/32"
	loopbackV6CIDR    = "::1/128"
	// telemtDefaultPort is the server.port telemt uses when the config omits it.
	telemtDefaultPort = 443
	// webMaxProfiles is the web.limits.max_profiles the node renders. telemt
	// reads it only at start, so it is fixed rather than sized per sync. Each
	// profile reserves 64 bytes of telemt's WEB memory envelope, and telemt's
	// default envelope (1280 MiB) has about 4.1 MiB to spare once its other
	// default reservations are counted: 65536 profiles take 4 MiB of it. A
	// render with more profiles (users times vhosts) is rejected by telemt.
	webMaxProfiles = 65536
)

var (
	validUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	restrictedAccessKeys = []string{
		"users",
		"user_ad_tags",
		"user_max_tcp_conns",
		"user_expirations",
		"user_data_quota",
		"user_max_unique_ips",
		"user_enabled",
	}
	// rejectedConfigKeys are telemt config paths the panel JSON must not set:
	// the node manages them, or they would reach past the node.
	rejectedConfigKeys = []rejectedConfigKey{
		{path: []string{"include"}, reason: "telemt would read other files on the node host"},
		{path: []string{"web", "debug"}, reason: "the WEB debug endpoint would expose node traffic records"},
		{path: []string{"web", "limits", "max_profiles"}, reason: "the node sets it"},
		{path: []string{"server", "api"}, reason: "the node manages the telemt control API"},
		{path: []string{"server", "admin_api"}, reason: "it is an alias of server.api, which the node manages"},
		{path: []string{"server", "metrics_port"}, reason: "the node manages the metrics endpoint"},
		{path: []string{"server", "metrics_listen"}, reason: "the node manages the metrics endpoint"},
		{path: []string{"server", "metrics_whitelist"}, reason: "the node manages the metrics endpoint"},
		{path: []string{"access", "user_rate_limits"}, reason: "per-user maps are keyed by node-managed usernames"},
		{path: []string{"access", "user_source_deny"}, reason: "per-user maps are keyed by node-managed usernames"},
	}
	// objectConfigPaths must hold a JSON object when present.
	objectConfigPaths = [][]string{
		{"general"},
		{"general", "telemetry"},
		{"server"},
		{"access"},
		{"logging"},
		{"web"},
		{"web", "limits"},
	}
)

type rejectedConfigKey struct {
	path   []string
	reason string
}

type Config struct {
	base        map[string]any
	InboundTag  string
	webProfiles []webUserProfile
}

type runtimeUser struct {
	Username     string
	Secret       string
	UserAdTag    string
	MaxTCPConns  uint32
	MaxUniqueIPs uint32
}

func NewConfig(raw string) (*Config, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("mtproto config string must not be empty")
	}

	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()

	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("failed to decode mtproto config JSON: %w", err)
	}

	var extra json.RawMessage
	switch err := decoder.Decode(&extra); {
	case errors.Is(err, io.EOF):
		// exactly one JSON document, as required
	case err != nil:
		return nil, fmt.Errorf("failed to decode trailing mtproto config JSON: %w", err)
	default:
		return nil, errors.New("mtproto config must contain exactly one JSON object")
	}

	cfg := &Config{
		base:       cloneMap(root),
		InboundTag: defaultInboundTag,
	}

	if inboundTagRaw, exists := cfg.base["inbound_tag"]; exists {
		inboundTag, ok := inboundTagRaw.(string)
		if !ok {
			return nil, errors.New("mtproto config field inbound_tag must be a string")
		}
		inboundTag = strings.TrimSpace(inboundTag)
		if inboundTag == "" {
			return nil, errors.New("mtproto config field inbound_tag must not be empty")
		}
		cfg.InboundTag = inboundTag
		delete(cfg.base, "inbound_tag")
	}

	if err := validateConfigRoot(cfg.base); err != nil {
		return nil, err
	}

	webProfiles, err := takeWebProfiles(cfg.base)
	if err != nil {
		return nil, err
	}
	cfg.webProfiles = webProfiles

	return cfg, nil
}

// validateConfigRoot checks the panel JSON. A JSON null counts as not set,
// matching the renderer, which drops null fields.
func validateConfigRoot(root map[string]any) error {
	if root == nil {
		return errors.New("mtproto config must be a JSON object")
	}

	for _, path := range objectConfigPaths {
		if _, err := objectAt(root, path...); err != nil {
			return err
		}
	}

	access, _ := objectAt(root, "access")
	for _, key := range restrictedAccessKeys {
		if isSet(access, key) {
			return fmt.Errorf("mtproto config must not define access.%s; node derives per-user access data", key)
		}
	}

	for _, rejected := range rejectedConfigKeys {
		last := len(rejected.path) - 1
		parent, err := objectAt(root, rejected.path[:last]...)
		if err != nil {
			return err
		}
		if isSet(parent, rejected.path[last]) {
			return fmt.Errorf("mtproto config must not define %s: %s", strings.Join(rejected.path, "."), rejected.reason)
		}
	}

	// telemt reads a key named include in any table as a file include (see
	// checkNoIncludeLines). The render refuses one too; rejecting it here
	// tells the panel at once.
	if path, found := findKey(root, "include", ""); found {
		return fmt.Errorf("mtproto config must not define %s: telemt would read other files on the node host", path)
	}

	if _, err := listenPorts(root); err != nil {
		return err
	}

	return validateListenerTransports(root)
}

// validateListenerTransports allows MTProxy listeners and WEB listeners that
// pass validateWebListener. Call it after listenPorts, which checks the
// listener shapes.
func validateListenerTransports(root map[string]any) error {
	server, _ := objectAt(root, "server")
	listeners, _ := server["listeners"].([]any)
	for index, rawListener := range listeners {
		listener, _ := rawListener.(map[string]any)
		if !isSet(listener, "transport") {
			continue
		}
		transport, _ := listener["transport"].(string)
		switch transport {
		case "mtproxy":
		case webTransport:
			if err := validateWebListener(index, listener, server); err != nil {
				return err
			}
		default:
			return fmt.Errorf("mtproto config field server.listeners[%d].transport must be \"mtproxy\" (or \"web\" for a WEB listener behind an HTTPS front)", index)
		}
	}
	return nil
}

// ListenPorts returns the client-facing TCP ports of the config, sorted and
// without duplicates: server.port (telemt's default 443 when unset) and every
// server.listeners[].port.
func (c *Config) ListenPorts() []int {
	if c == nil {
		return nil
	}
	ports, _ := listenPorts(c.base)
	return ports
}

func listenPorts(root map[string]any) ([]int, error) {
	server, err := objectAt(root, "server")
	if err != nil {
		return nil, err
	}

	serverPort := telemtDefaultPort
	if isSet(server, "port") {
		if serverPort, err = portValue("server.port", server["port"]); err != nil {
			return nil, err
		}
	}
	ports := []int{serverPort}

	if isSet(server, "listeners") {
		listeners, ok := server["listeners"].([]any)
		if !ok {
			return nil, errors.New("mtproto config field server.listeners must be an array of objects")
		}
		for index, rawListener := range listeners {
			listener, ok := rawListener.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("mtproto config field server.listeners[%d] must be an object", index)
			}
			// A listener without a port uses server.port, already listed.
			if !isSet(listener, "port") {
				continue
			}
			port, err := portValue(fmt.Sprintf("server.listeners[%d].port", index), listener["port"])
			if err != nil {
				return nil, err
			}
			ports = append(ports, port)
		}
	}

	slices.Sort(ports)
	return slices.Compact(ports), nil
}

func portValue(field string, value any) (int, error) {
	var port int64
	switch typed := value.(type) {
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("mtproto config field %s must be an integer port, got %s", field, typed)
		}
		port = parsed
	case int:
		port = int64(typed)
	case int64:
		port = typed
	default:
		return 0, fmt.Errorf("mtproto config field %s must be an integer port", field)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("mtproto config field %s must be between 1 and 65535, got %d", field, port)
	}
	return int(port), nil
}

func (c *Config) Render(users map[string]*runtimeUser, marker *runtimeUser, apiPort, metricsPort int, apiAuthHeader string) (string, error) {
	if c == nil {
		return "", errors.New("mtproto config is nil")
	}

	ports, err := listenPorts(c.base)
	if err != nil {
		return "", err
	}
	for _, port := range ports {
		switch port {
		case apiPort:
			return "", fmt.Errorf("mtproto config listen port %d conflicts with the node's telemt API port", port)
		case metricsPort:
			return "", fmt.Errorf("mtproto config listen port %d conflicts with the node's telemt metrics port", port)
		}
	}

	if err := checkDecoyPorts(c.base, apiPort, metricsPort); err != nil {
		return "", err
	}

	root := cloneMap(c.base)
	general := ensureObject(root, "general")
	telemetry := ensureObject(general, "telemetry")
	server := ensureObject(root, "server")
	api := ensureObject(server, "api")
	access := ensureObject(root, "access")
	logging := ensureObject(root, "logging")

	// The node reads telemt's stderr for its log stream and startup errors,
	// and streams it to the panel log viewer, where ANSI colours are noise.
	// Per-user counters feed traffic accounting; with user telemetry off
	// telemt reports zero for every user.
	logging["destination"] = "stderr"
	general["disable_colors"] = true
	telemetry["user_enabled"] = true

	// metrics_port enables the Prometheus endpoint; metrics_listen pins it to
	// loopback. telemt treats metrics_port as the enable flag, so both are set.
	server["metrics_port"] = metricsPort
	server["metrics_listen"] = fmt.Sprintf("127.0.0.1:%d", metricsPort)
	server["metrics_whitelist"] = []any{loopbackV4CIDR, loopbackV6CIDR}

	api["enabled"] = true
	api["read_only"] = false
	api["listen"] = fmt.Sprintf("127.0.0.1:%d", apiPort)
	api["auth_header"] = apiAuthHeader
	api["whitelist"] = []any{loopbackV4CIDR, loopbackV6CIDR}

	if err := applyUsersToAccess(access, users, marker); err != nil {
		return "", err
	}
	if c.HasWeb() {
		if err := checkWebProfileCount(len(c.webProfiles), len(users)); err != nil {
			return "", err
		}
		applyWebProfiles(root, c.webProfiles, users, marker)
	}

	return renderTOML(root)
}

// checkWebProfileCount refuses a render with more WEB profiles than
// webMaxProfiles. telemt counts profiles across all vhosts and refuses the
// whole config above web.limits.max_profiles. Every vhost gets one profile per
// user; the marker's single profile per vhost, used only without users, never
// reaches the limit.
func checkWebProfileCount(vhostCount, userCount int) error {
	if total := vhostCount * userCount; total > webMaxProfiles {
		return fmt.Errorf("mtproto config would need %d WEB profiles (%d users x %d vhosts), above the %d the node allows", total, userCount, vhostCount, webMaxProfiles)
	}
	return nil
}

// applyWebProfiles gives every WEB vhost one profile per user, built from the
// vhost's user_profile template, and sets web.limits.max_profiles. With no
// users the marker gets the profile instead: telemt rejects an enabled vhost
// without profiles.
func applyWebProfiles(root map[string]any, profiles []webUserProfile, users map[string]*runtimeUser, marker *runtimeUser) {
	usernames := slices.Sorted(maps.Keys(users))
	if len(usernames) == 0 && marker != nil {
		usernames = []string{marker.Username}
	}

	web := ensureObject(root, "web")
	vhosts, _ := web["vhosts"].([]any)
	for index, rawVhost := range vhosts {
		vhost, _ := rawVhost.(map[string]any)
		template := profiles[index]
		rendered := make([]any, 0, len(usernames))
		for _, username := range usernames {
			profile := map[string]any{"user": username, "secret_mode": template.SecretMode}
			if template.MaxSessions > 0 {
				profile["max_sessions"] = template.MaxSessions
			}
			if template.MaxStreams > 0 {
				profile["max_streams"] = template.MaxStreams
			}
			if template.MaxStreamsPerSession > 0 {
				profile["max_streams_per_session"] = template.MaxStreamsPerSession
			}
			rendered = append(rendered, profile)
		}
		vhost["profiles"] = rendered
	}
	ensureObject(web, "limits")["max_profiles"] = webMaxProfiles
}

func applyUsersToAccess(access map[string]any, users map[string]*runtimeUser, marker *runtimeUser) error {
	if len(users) == 0 && marker == nil {
		return errors.New("mtproto config requires at least one user or a marker user")
	}

	userSecrets := make(map[string]any, len(users)+1)
	userAdTags := make(map[string]any)
	userMaxTCPConns := make(map[string]any)
	userMaxUniqueIPs := make(map[string]any)
	userEnabled := make(map[string]any)

	usernames := make([]string, 0, len(users))
	for username := range users {
		usernames = append(usernames, username)
	}
	slices.Sort(usernames)

	for _, username := range usernames {
		user := users[username]
		userSecrets[username] = user.Secret
		if user.UserAdTag != "" {
			userAdTags[username] = user.UserAdTag
		}
		if user.MaxTCPConns > 0 {
			userMaxTCPConns[username] = user.MaxTCPConns
		}
		if user.MaxUniqueIPs > 0 {
			userMaxUniqueIPs[username] = user.MaxUniqueIPs
		}
	}

	if marker != nil {
		// The marker keeps [access.users] non-empty so telemt will start; it
		// is disabled so it cannot authenticate as a real MTProto client.
		userSecrets[marker.Username] = marker.Secret
		userEnabled[marker.Username] = false
	}

	access["users"] = userSecrets
	writeOptionalMap(access, "user_ad_tags", userAdTags)
	writeOptionalMap(access, "user_max_tcp_conns", userMaxTCPConns)
	writeOptionalMap(access, "user_max_unique_ips", userMaxUniqueIPs)
	writeOptionalMap(access, "user_enabled", userEnabled)

	return nil
}

func writeOptionalMap(target map[string]any, key string, values map[string]any) {
	if len(values) == 0 {
		delete(target, key)
		return
	}
	target[key] = values
}

// ActiveUsersFromCommon returns the users that carry inboundTag, keyed by
// username. A tagged user that fails validation is logged and left out, so one
// bad record cannot fail a whole sync; the second value lists their emails.
func ActiveUsersFromCommon(users []*common.User, inboundTag string) (map[string]*runtimeUser, []string) {
	active := make(map[string]*runtimeUser)
	var skipped []string
	seenSkipped := make(map[string]struct{})
	for _, user := range users {
		if user == nil {
			continue
		}
		runtimeUser, include, err := activeUserFromCommon(user, inboundTag)
		if err != nil {
			email := strings.TrimSpace(user.GetEmail())
			if _, seen := seenSkipped[email]; !seen {
				seenSkipped[email] = struct{}{}
				skipped = append(skipped, email)
				logSkippedUser(email, err)
			}
			continue
		}
		if include {
			active[runtimeUser.Username] = runtimeUser
		}
	}
	return active, skipped
}

func logSkippedUser(email string, err error) {
	log.Printf("mtproto: skipping user %s: %v", email, err)
}

func activeUserFromCommon(user *common.User, inboundTag string) (*runtimeUser, bool, error) {
	if user == nil {
		return nil, false, errors.New("mtproto user must not be nil")
	}

	if !slices.Contains(user.GetInbounds(), inboundTag) {
		return nil, false, nil
	}

	username := strings.TrimSpace(user.GetEmail())
	if !validUsernamePattern.MatchString(username) {
		return nil, false, fmt.Errorf("invalid mtproto username %q; expected [A-Za-z0-9_.-] and length 1..64", username)
	}
	// Usernames are TOML keys, and telemt reads a key named include as a file
	// include (see checkNoIncludeLines). Skipping the user here keeps one bad
	// record from failing the whole render.
	if username == "include" {
		return nil, false, fmt.Errorf("invalid mtproto username %q; telemt reserves it", username)
	}

	proxy := user.GetProxies().GetMtproto()
	if proxy == nil {
		return nil, false, fmt.Errorf("mtproto user %q is missing proxies.mtproto", username)
	}

	secret := strings.TrimSpace(proxy.GetSecret())
	if !isHex32(secret) {
		return nil, false, fmt.Errorf("mtproto user %q has an invalid secret; expected exactly 32 hex characters", username)
	}

	userAdTag := strings.TrimSpace(proxy.GetUserAdTag())
	if userAdTag != "" && !isHex32(userAdTag) {
		return nil, false, fmt.Errorf("mtproto user %q has an invalid user_ad_tag; expected exactly 32 hex characters", username)
	}

	return &runtimeUser{
		Username:     username,
		Secret:       strings.ToLower(secret),
		UserAdTag:    strings.ToLower(userAdTag),
		MaxTCPConns:  proxy.GetMaxTcpConns(),
		MaxUniqueIPs: proxy.GetMaxUniqueIps(),
	}, true, nil
}

// objectAt returns the object at path, or nil when any part of the path is
// absent or null. A part that holds something other than an object is an error.
func objectAt(root map[string]any, path ...string) (map[string]any, error) {
	current := root
	for index, key := range path {
		if current == nil {
			return nil, nil
		}
		raw := current[key]
		if raw == nil {
			return nil, nil
		}
		child, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("mtproto config field %s must be an object", strings.Join(path[:index+1], "."))
		}
		current = child
	}
	return current, nil
}

func isSet(object map[string]any, key string) bool {
	return object != nil && object[key] != nil
}

// findKey returns the path of the first set key named key at any depth of
// value, tables inside arrays included.
func findKey(value any, key, path string) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for _, name := range slices.Sorted(maps.Keys(typed)) {
			namePath := appendTOMLPath(path, name)
			if name == key && typed[name] != nil {
				return namePath, true
			}
			if found, ok := findKey(typed[name], key, namePath); ok {
				return found, true
			}
		}
	case []any:
		for index, item := range typed {
			if found, ok := findKey(item, key, fmt.Sprintf("%s[%d]", path, index)); ok {
				return found, true
			}
		}
	}
	return "", false
}

func ensureObject(target map[string]any, key string) map[string]any {
	if existing, ok := target[key]; ok {
		if existingMap, ok := existing.(map[string]any); ok {
			return existingMap
		}
	}

	child := make(map[string]any)
	target[key] = child
	return child
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}

	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = cloneValue(value)
	}
	return cloned
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		cloned := make([]any, len(typed))
		for i, item := range typed {
			cloned[i] = cloneValue(item)
		}
		return cloned
	default:
		return typed
	}
}

func isHex32(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
