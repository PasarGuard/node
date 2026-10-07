package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"

	"github.com/pasarguard/node/common"
)

type Config struct {
	ServicePort            int
	NodeHost               string
	XrayExecutablePath     string
	XrayAssetsPath         string
	SingBoxExecutablePath  string
	SingBoxSyncDebounce    time.Duration
	SingBoxAllowNoV2RayAPI bool
	SslCertFile            string
	SslKeyFile             string
	ApiKey                 uuid.UUID
	ServiceProtocol        string
	Debug                  bool
	GeneratedConfigPath    string
	LogBufferSize          int
	StartupLogTailSize     int
	// QuotaSecret authorises the quota control endpoint. It is generated at
	// start (or read from SINGBOX_QUOTA_SECRET) and handed only to the sing-box
	// child's environment: it is never written to the config, the logs, or any
	// file. The config file is copied into images and crash dumps, so it is not
	// a boundary for a value that lets anyone raise a data limit.
	QuotaSecret                 string
	StatsUpdateIntervalSeconds  int
	StatsCleanupIntervalSeconds int

	// WireGuard host routing (Linux). See .env.example for semantics.
	WGHostRouting        bool
	WGNATOutputInterface string
	WGNATEgressOnly      bool
	WGNATDisable         bool
	WGRouteTable         string
	WGRouteOutInterface  string

	// Role is the node's role (CONTRACT §1.7): proxy (default, today's
	// behaviour) or tunnel. A tunnel node runs no proxy cores and holds no
	// users; the role comes from NODE_ROLE and is not synced from the panel —
	// a panel/node mismatch shows up in Preflight and status, never silently.
	Role common.NodeRole
	// TunnelBundleDir is the operator's offline bundle of pinned tunnel
	// binaries (TUNNEL_BUNDLE_DIR). Empty means "no bundle"; nothing is ever
	// downloaded at runtime without it (CONTRACT §2.1).
	TunnelBundleDir string
}

// quotaSecretEnv is the environment variable the sing-box child reads; the same
// name is used by the core patch (experimental/v2rayapi/quota.go).
const quotaSecretEnv = "SINGBOX_QUOTA_SECRET"

// NewQuotaSecret returns an operator-supplied secret if one exists, otherwise a
// fresh random one. crypto/rand, not math/rand: this value authenticates an
// endpoint that can raise data limits.
func NewQuotaSecret() string {
	if fromEnv := GetEnv(quotaSecretEnv, ""); fromEnv != "" {
		return fromEnv
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// A node that cannot generate entropy must not silently run without a
		// secret: an empty one disables the endpoint entirely, which is the
		// safe outcome, but it should be visible rather than accidental.
		log.Printf("[Warning] could not generate a quota secret (%v); the quota control endpoint will be disabled", err)
		return ""
	}
	return hex.EncodeToString(buf)
}

func Load() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		log.Printf("[Warning] Failed to load env file, if you're using 'Docker' and you set 'environment' or 'env_file' variable, don't worry, everything is fine. Error: %v", err)
	}

	cfg := &Config{
		ServicePort:                 GetEnvAsInt("SERVICE_PORT", 62050),
		XrayExecutablePath:          GetEnv("XRAY_EXECUTABLE_PATH", "/usr/local/bin/xray"),
		XrayAssetsPath:              GetEnv("XRAY_ASSETS_PATH", "/usr/local/share/xray"),
		SingBoxExecutablePath:       GetEnv("SINGBOX_EXECUTABLE_PATH", "/usr/local/bin/sing-box"),
		SingBoxSyncDebounce:         time.Duration(GetEnvAsInt("SINGBOX_SYNC_DEBOUNCE_SECONDS", 30)) * time.Second,
		SingBoxAllowNoV2RayAPI:      GetEnvAsBool("SINGBOX_ALLOW_MISSING_V2RAY_API", false),
		SslCertFile:                 GetEnv("SSL_CERT_FILE", "/var/lib/pg-node/certs/ssl_cert.pem"),
		SslKeyFile:                  GetEnv("SSL_KEY_FILE", "/var/lib/pg-node/certs/ssl_key.pem"),
		GeneratedConfigPath:         GetEnv("GENERATED_CONFIG_PATH", "/var/lib/pg-node/generated/"),
		ServiceProtocol:             GetEnv("SERVICE_PROTOCOL", "grpc"),
		Debug:                       GetEnvAsBool("DEBUG", false),
		LogBufferSize:               GetEnvAsInt("LOG_BUFFER_SIZE", 10000),
		StartupLogTailSize:          GetEnvAsInt("STARTUP_LOG_TAIL_SIZE", 200),
		QuotaSecret:                 NewQuotaSecret(),
		StatsUpdateIntervalSeconds:  GetEnvAsInt("STATS_UPDATE_INTERVAL_SECONDS", 10),
		StatsCleanupIntervalSeconds: GetEnvAsInt("STATS_CLEANUP_INTERVAL_SECONDS", 300),

		WGHostRouting:        GetEnvAsBool("PG_NODE_WG_HOST_ROUTING", true),
		WGNATOutputInterface: GetEnv("PG_NODE_WG_NAT_OUTPUT_INTERFACE", ""),
		WGNATEgressOnly:      GetEnvAsBool("PG_NODE_WG_NAT_EGRESS_ONLY", true),
		WGNATDisable:         GetEnvAsBool("PG_NODE_WG_NAT_DISABLE", false),
		WGRouteTable:         GetEnv("PG_NODE_WG_ROUTE_TABLE", ""),
		WGRouteOutInterface:  GetEnv("PG_NODE_WG_ROUTE_OUT_INTERFACE", ""),

		Role:            ParseRole(GetEnv("NODE_ROLE", "proxy")),
		TunnelBundleDir: GetEnv("TUNNEL_BUNDLE_DIR", ""),
	}

	if cfg.LogBufferSize <= 0 {
		log.Printf("[Warning] LOG_BUFFER_SIZE must be greater than 0, got %d. Falling back to 1.", cfg.LogBufferSize)
		cfg.LogBufferSize = 1
	}

	cfg.ApiKey, err = GetEnvAsUUID("API_KEY")
	if err != nil {
		log.Printf("[Error] Failed to load API Key, error: %v", err)
	}

	nodeHostStr := GetEnv("NODE_HOST", "0.0.0.0")
	ipPattern := `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	re := regexp.MustCompile(ipPattern)

	if re.MatchString(nodeHostStr) {
		cfg.NodeHost = nodeHostStr
	} else {
		log.Println(nodeHostStr, " is not a valid IP address.\n NODE_HOST will be set to 127.0.0.1")
		cfg.NodeHost = "127.0.0.1"
	}

	return cfg, nil
}

// ForCore returns a shallow copy of cfg whose GeneratedConfigPath points at
// that core's own directory.
//
// core_id 0 is the node's default/only core and lands in core-1/, so a
// single-core node's config path changes but nothing else about it does. Two
// same-type cores can no longer overwrite each other's config file.
//
// CoreID 0 in, core-1 out: the default core is the first core.
func (c *Config) ForCore(coreID uint64) *Config {
	if coreID == 0 {
		coreID = 1
	}
	scoped := *c
	scoped.GeneratedConfigPath = CoreConfigPath(c.GeneratedConfigPath, coreID)
	return &scoped
}

// CoreConfigPath is the per-core config directory under generatedConfigPath.
func CoreConfigPath(generatedConfigPath string, coreID uint64) string {
	return filepath.Join(generatedConfigPath, fmt.Sprintf("core-%d", coreID))
}

// NewTestConfig creates a config for testing
func NewTestConfig(generatedConfigPath string, key uuid.UUID) *Config {
	cfg, _ := Load()
	cfg.GeneratedConfigPath = generatedConfigPath
	cfg.ApiKey = key
	// tests assert synchronous apply; debounce tests set this explicitly
	cfg.SingBoxSyncDebounce = 0
	return cfg
}

func GetEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

// ParseRole maps NODE_ROLE onto the proto enum (CONTRACT §1.7). Anything that
// is not "tunnel" is a proxy node with today's behaviour, and an unknown value
// says so in the log rather than being silently ignored.
func ParseRole(v string) common.NodeRole {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "proxy":
		return common.NodeRole_NODE_ROLE_PROXY
	case "tunnel":
		return common.NodeRole_NODE_ROLE_TUNNEL
	default:
		log.Printf("[Warning] NODE_ROLE=%q is not proxy|tunnel; running as a proxy node", v)
		return common.NodeRole_NODE_ROLE_PROXY
	}
}

// IsTunnelRole reports whether this node runs tunnels only: no proxy cores,
// no users (CONTRACT §1.7).
func (c *Config) IsTunnelRole() bool {
	return c != nil && c.Role == common.NodeRole_NODE_ROLE_TUNNEL
}

func GetEnvAsBool(name string, defaultVal bool) bool {
	valStr := GetEnv(name, "")
	if val, err := strconv.ParseBool(valStr); err == nil {
		return val
	}
	return defaultVal
}

func GetEnvAsInt(name string, defaultVal int) int {
	valStr := GetEnv(name, "")
	if val, err := strconv.Atoi(valStr); err == nil {
		return val
	}
	return defaultVal
}

func GetEnvAsUUID(name string) (uuid.UUID, error) {
	valStr := GetEnv(name, "")

	val, err := uuid.Parse(valStr)
	if err != nil {
		return uuid.Nil, err
	}
	return val, nil
}
