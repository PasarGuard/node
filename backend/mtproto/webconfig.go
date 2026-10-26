package mtproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const (
	webTransport       = "web"
	webSecretModeDD    = "dd"
	webSecretModePlain = "plain"
)

// webUserProfileLimits are the optional numeric keys of a vhost user_profile.
var webUserProfileLimits = []string{"max_sessions", "max_streams", "max_streams_per_session"}

// webUserProfile is the per-vhost template the node applies to every user it
// exposes through that vhost. A zero limit means unset.
type webUserProfile struct {
	SecretMode           string
	MaxSessions          uint32
	MaxStreams           uint32
	MaxStreamsPerSession uint32
}

// HasWeb reports whether the config enables telemt's WEB mode with at least
// one vhost.
func (c *Config) HasWeb() bool {
	if c == nil {
		return false
	}
	web, _ := objectAt(c.base, "web")
	enabled, _ := web["enabled"].(bool)
	vhosts, _ := web["vhosts"].([]any)
	return enabled && len(vhosts) > 0
}

// validateWebListener checks one listener with transport "web". It must sit
// on a loopback or private address behind the admin's HTTPS front, and on its
// own port: telemt cannot share a port between transports.
func validateWebListener(index int, listener map[string]any, server map[string]any) error {
	ipText, _ := listener["ip"].(string)
	ip := net.ParseIP(ipText)
	if ip == nil || ip.IsUnspecified() || !(ip.IsLoopback() || ip.IsPrivate()) {
		return fmt.Errorf("mtproto config field server.listeners[%d].ip must be a loopback or private address for a web listener; put an HTTPS front in front of it", index)
	}
	if !isSet(listener, "port") {
		return fmt.Errorf("mtproto config field server.listeners[%d].port must be set for a web listener", index)
	}
	port, err := portValue(fmt.Sprintf("server.listeners[%d].port", index), listener["port"])
	if err != nil {
		return err
	}

	serverPort := telemtDefaultPort
	if isSet(server, "port") {
		if serverPort, err = portValue("server.port", server["port"]); err != nil {
			return err
		}
	}
	if port == serverPort {
		return fmt.Errorf("mtproto config field server.listeners[%d].port %d must differ from server.port", index, port)
	}
	listeners, _ := server["listeners"].([]any)
	for other, rawListener := range listeners {
		native, _ := rawListener.(map[string]any)
		if transport, _ := native["transport"].(string); transport == webTransport {
			continue
		}
		nativePort := serverPort
		if isSet(native, "port") {
			if nativePort, err = portValue(fmt.Sprintf("server.listeners[%d].port", other), native["port"]); err != nil {
				return err
			}
		}
		if port == nativePort {
			return fmt.Errorf("mtproto config field server.listeners[%d].port %d must differ from the port of MTProxy listener server.listeners[%d]", index, port, other)
		}
	}
	return nil
}

// takeWebProfiles validates the web section against the listeners, removes
// each vhost's user_profile from root and returns the profiles index-aligned
// with web.vhosts. Call it after validateConfigRoot.
func takeWebProfiles(root map[string]any) ([]webUserProfile, error) {
	web, err := objectAt(root, "web")
	if err != nil {
		return nil, err
	}

	enabled := false
	if isSet(web, "enabled") {
		var ok bool
		if enabled, ok = web["enabled"].(bool); !ok {
			return nil, errors.New("mtproto config field web.enabled must be a boolean")
		}
	}

	var vhosts []any
	if isSet(web, "vhosts") {
		var ok bool
		if vhosts, ok = web["vhosts"].([]any); !ok {
			return nil, errors.New("mtproto config field web.vhosts must be an array of objects")
		}
	}

	server, _ := objectAt(root, "server")
	listeners, _ := server["listeners"].([]any)
	hasWebListener := slices.ContainsFunc(listeners, func(raw any) bool {
		listener, _ := raw.(map[string]any)
		transport, _ := listener["transport"].(string)
		return transport == webTransport
	})
	switch {
	case enabled && !hasWebListener:
		return nil, errors.New("mtproto config field web.enabled needs a server.listeners entry with transport \"web\"")
	case hasWebListener && (!enabled || len(vhosts) == 0):
		return nil, errors.New("mtproto config web listeners need web.enabled set to true and at least one web.vhosts entry")
	}

	if len(vhosts) == 0 {
		return nil, nil
	}
	profiles := make([]webUserProfile, len(vhosts))
	for index, rawVhost := range vhosts {
		vhost, ok := rawVhost.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("mtproto config field web.vhosts[%d] must be an object", index)
		}
		if isSet(vhost, "profiles") {
			return nil, fmt.Errorf("mtproto config must not define web.vhosts[%d].profiles: the node builds them from its users", index)
		}
		if err := validateWebBasePath(index, vhost["base_path"]); err != nil {
			return nil, err
		}
		if err := validateWebDecoy(index, vhost["decoy"]); err != nil {
			return nil, err
		}
		if profiles[index], err = webUserProfileValue(index, vhost["user_profile"]); err != nil {
			return nil, err
		}
	}
	for _, rawVhost := range vhosts {
		delete(rawVhost.(map[string]any), "user_profile")
	}
	return profiles, nil
}

// webBasePathMaxBytes is telemt's length limit for a vhost base_path.
const webBasePathMaxBytes = 128

// validateWebBasePath applies telemt's validate_web_base_path: base_path is
// empty, or at most 128 ASCII bytes of slash-separated segments that each
// match [A-Za-z0-9][A-Za-z0-9_-]*, with no leading or trailing slash. telemt
// uses the value as is, so a value it refuses at Start is refused here first.
func validateWebBasePath(index int, rawBasePath any) error {
	if rawBasePath == nil {
		return nil
	}
	field := fmt.Sprintf("web.vhosts[%d].base_path", index)
	basePath, ok := rawBasePath.(string)
	if !ok {
		return fmt.Errorf("mtproto config field %s must be a string", field)
	}
	if basePath == "" {
		return nil
	}
	valid := len(basePath) <= webBasePathMaxBytes
	for segment := range strings.SplitSeq(basePath, "/") {
		valid = valid && segment != "" && isASCIIAlphanumeric(segment[0]) &&
			strings.IndexFunc(segment, func(r rune) bool {
				return !(r < 0x80 && (isASCIIAlphanumeric(byte(r)) || r == '-' || r == '_'))
			}) < 0
	}
	if !valid {
		return fmt.Errorf("mtproto config field %s must be empty or at most %d ASCII bytes of slash-separated [A-Za-z0-9][A-Za-z0-9_-]* segments, without a leading or trailing slash", field, webBasePathMaxBytes)
	}
	return nil
}

func isASCIIAlphanumeric(b byte) bool {
	return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || ('0' <= b && b <= '9')
}

// validateWebDecoy allows only an http_upstream decoy whose upstream host is a
// loopback or private IP literal: static_directory would serve files from the
// node host, and a public or named upstream would reach past the node. The
// upstream must also be a bare http origin, as telemt's decoy_dns::parse_origin
// requires, so a value telemt refuses at Start is refused here first.
func validateWebDecoy(index int, rawDecoy any) error {
	field := fmt.Sprintf("web.vhosts[%d].decoy", index)
	decoy, ok := rawDecoy.(map[string]any)
	if !ok {
		return fmt.Errorf("mtproto config field %s must be an object", field)
	}
	switch mode, _ := decoy["mode"].(string); mode {
	case "http_upstream":
	case "static_directory":
		return fmt.Errorf("mtproto config field %s.mode must not be \"static_directory\": it would serve files from the node host", field)
	default:
		return fmt.Errorf("mtproto config field %s.mode must be \"http_upstream\"", field)
	}

	upstream, _ := decoy["upstream"].(string)
	parsed, ok := parseHTTPOrigin(upstream)
	if !ok {
		return fmt.Errorf("mtproto config field %s.upstream must be an http origin without credentials, path, query, or fragment", field)
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || ip.IsUnspecified() || !(ip.IsLoopback() || ip.IsPrivate()) {
		return fmt.Errorf("mtproto config field %s.upstream must use a loopback or private IP address as its host", field)
	}
	return nil
}

// checkDecoyPorts refuses a decoy upstream on a loopback host and the node's
// telemt API or metrics port: the decoy connects from loopback, so the WEB
// domain would publish that endpoint. Only Render knows the two ports.
func checkDecoyPorts(base map[string]any, apiPort, metricsPort int) error {
	web, _ := base["web"].(map[string]any)
	vhosts, _ := web["vhosts"].([]any)
	for index, rawVhost := range vhosts {
		vhost, _ := rawVhost.(map[string]any)
		decoy, _ := vhost["decoy"].(map[string]any)
		upstream, _ := decoy["upstream"].(string)
		origin, ok := parseHTTPOrigin(upstream)
		if !ok {
			continue
		}
		if ip := net.ParseIP(origin.Hostname()); ip == nil || !ip.IsLoopback() {
			continue
		}
		field := fmt.Sprintf("web.vhosts[%d].decoy.upstream", index)
		switch port := decoyOriginPort(origin); port {
		case apiPort:
			return fmt.Errorf("mtproto config field %s port %d conflicts with the node's telemt API port", field, port)
		case metricsPort:
			return fmt.Errorf("mtproto config field %s port %d conflicts with the node's telemt metrics port", field, port)
		}
	}
	return nil
}

// parseHTTPOrigin parses an http URL with a host, an optional port in
// 1-65535, a path of "" or "/", and no userinfo, query or fragment.
func parseHTTPOrigin(raw string) (*url.URL, bool) {
	// url.Parse drops an empty "#", and "?" only sets ForceQuery, so both
	// characters are checked on the raw string.
	if strings.ContainsAny(raw, "?#") {
		return nil, false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return nil, false
	}
	if port := parsed.Port(); port != "" {
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return nil, false
		}
	}
	return parsed, true
}

// decoyOriginPort is the TCP port an origin from parseHTTPOrigin connects to.
func decoyOriginPort(origin *url.URL) int {
	if port := origin.Port(); port != "" {
		number, _ := strconv.Atoi(port)
		return number
	}
	return 80
}

func webUserProfileValue(index int, raw any) (webUserProfile, error) {
	profile := webUserProfile{SecretMode: webSecretModeDD}
	if raw == nil {
		return profile, nil
	}
	field := fmt.Sprintf("web.vhosts[%d].user_profile", index)
	object, ok := raw.(map[string]any)
	if !ok {
		return profile, fmt.Errorf("mtproto config field %s must be an object", field)
	}
	for key := range object {
		if key != "secret_mode" && !slices.Contains(webUserProfileLimits, key) {
			return profile, fmt.Errorf("mtproto config field %s.%s is not supported", field, key)
		}
	}

	if isSet(object, "secret_mode") {
		mode, _ := object["secret_mode"].(string)
		if mode != webSecretModeDD && mode != webSecretModePlain {
			return profile, fmt.Errorf("mtproto config field %s.secret_mode must be \"dd\" or \"plain\"", field)
		}
		profile.SecretMode = mode
	}

	limits := []*uint32{&profile.MaxSessions, &profile.MaxStreams, &profile.MaxStreamsPerSession}
	for i, key := range webUserProfileLimits {
		if !isSet(object, key) {
			continue
		}
		number, ok := object[key].(json.Number)
		value, err := number.Int64()
		if !ok || err != nil || value < 0 || value > math.MaxUint32 {
			return profile, fmt.Errorf("mtproto config field %s.%s must be a non-negative integer", field, key)
		}
		*limits[i] = uint32(value)
	}
	return profile, nil
}
