package mtproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/pasarguard/node/common"
)

const (
	defaultInboundTag = "mtproto"
	loopbackV4CIDR    = "127.0.0.1/32"
	loopbackV6CIDR    = "::1/128"
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
)

type Config struct {
	base       map[string]any
	InboundTag string
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

	return cfg, nil
}

func validateConfigRoot(root map[string]any) error {
	if root == nil {
		return errors.New("mtproto config must be a JSON object")
	}

	if accessRaw, exists := root["access"]; exists {
		access, ok := accessRaw.(map[string]any)
		if !ok {
			return errors.New("mtproto config field access must be an object")
		}
		for _, key := range restrictedAccessKeys {
			if _, forbidden := access[key]; forbidden {
				return fmt.Errorf("mtproto config must not define access.%s; node derives per-user access data", key)
			}
		}
	}

	if serverRaw, exists := root["server"]; exists {
		if _, ok := serverRaw.(map[string]any); !ok {
			return errors.New("mtproto config field server must be an object")
		}
	}

	return nil
}

func (c *Config) Render(users map[string]*runtimeUser, sentinel *runtimeUser, apiPort, metricsPort int, apiAuthHeader string) (string, error) {
	if c == nil {
		return "", errors.New("mtproto config is nil")
	}

	root := cloneMap(c.base)
	server := ensureObject(root, "server")
	api := ensureObject(server, "api")
	access := ensureObject(root, "access")

	// metrics_port enables the Prometheus endpoint; metrics_listen pins it to
	// loopback. telemt treats metrics_port as the enable flag, so both are set.
	server["metrics_port"] = metricsPort
	server["metrics_listen"] = fmt.Sprintf("127.0.0.1:%d", metricsPort)
	server["metrics_whitelist"] = []any{loopbackV4CIDR, loopbackV6CIDR}

	api["enabled"] = true
	api["listen"] = fmt.Sprintf("127.0.0.1:%d", apiPort)
	api["auth_header"] = apiAuthHeader
	api["whitelist"] = []any{loopbackV4CIDR, loopbackV6CIDR}

	if err := applyUsersToAccess(access, users, sentinel); err != nil {
		return "", err
	}

	return renderTOML(root)
}

func applyUsersToAccess(access map[string]any, users map[string]*runtimeUser, sentinel *runtimeUser) error {
	if len(users) == 0 && sentinel == nil {
		return errors.New("mtproto config requires at least one user or sentinel")
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

	if sentinel != nil {
		// Keep [access.users] non-empty so telemt will start, but disable the
		// sentinel so it cannot authenticate as a real MTProto client.
		userSecrets[sentinel.Username] = sentinel.Secret
		userEnabled[sentinel.Username] = false
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

func ActiveUsersFromCommon(users []*common.User, inboundTag string) (map[string]*runtimeUser, error) {
	active := make(map[string]*runtimeUser)
	for _, user := range users {
		runtimeUser, include, err := activeUserFromCommon(user, inboundTag)
		if err != nil {
			return nil, err
		}
		if include {
			active[runtimeUser.Username] = runtimeUser
		}
	}
	return active, nil
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
