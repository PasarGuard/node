package config

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

type Config struct {
	TLSEnabled                  bool
	ServicePort                 int
	NodeHost                    string
	XrayExecutablePath          string
	TelemtExecutablePath        string
	XrayAssetsPath              string
	SslCertFile                 string
	SslKeyFile                  string
	ApiKey                      uuid.UUID
	ServiceProtocol             string
	Debug                       bool
	GeneratedConfigPath         string
	LogBufferSize               int
	StartupLogTailSize          int
	StatsUpdateIntervalSeconds  int
	StatsCleanupIntervalSeconds int

	// WireGuard host routing (Linux). See .env.example for semantics.
	WGHostRouting        bool
	WGNATOutputInterface string
	WGNATEgressOnly      bool
	WGNATDisable         bool
	WGRouteTable         string
	WGRouteOutInterface  string
}

func Load() (*Config, error) {
	err := godotenv.Load()
	if err != nil {
		log.Printf("[Warning] Failed to load env file, if you're using 'Docker' and you set 'environment' or 'env_file' variable, don't worry, everything is fine. Error: %v", err)
	}

	cfg := &Config{
		TLSEnabled:                  true,
		ServicePort:                 GetEnvAsInt("SERVICE_PORT", 62050),
		XrayExecutablePath:          GetEnv("XRAY_EXECUTABLE_PATH", "/usr/local/bin/xray"),
		TelemtExecutablePath:        GetEnv("TELEMT_EXECUTABLE_PATH", "/usr/local/bin/telemt"),
		XrayAssetsPath:              GetEnv("XRAY_ASSETS_PATH", "/usr/local/share/xray"),
		SslCertFile:                 GetEnv("SSL_CERT_FILE", "/var/lib/pg-node/certs/ssl_cert.pem"),
		SslKeyFile:                  GetEnv("SSL_KEY_FILE", "/var/lib/pg-node/certs/ssl_key.pem"),
		GeneratedConfigPath:         GetEnv("GENERATED_CONFIG_PATH", "/var/lib/pg-node/generated/"),
		ServiceProtocol:             GetEnv("SERVICE_PROTOCOL", "grpc"),
		Debug:                       GetEnvAsBool("DEBUG", false),
		LogBufferSize:               GetEnvAsInt("LOG_BUFFER_SIZE", 10000),
		StartupLogTailSize:          GetEnvAsInt("STARTUP_LOG_TAIL_SIZE", 200),
		StatsUpdateIntervalSeconds:  GetEnvAsInt("STATS_UPDATE_INTERVAL_SECONDS", 10),
		StatsCleanupIntervalSeconds: GetEnvAsInt("STATS_CLEANUP_INTERVAL_SECONDS", 300),

		WGHostRouting:        GetEnvAsBool("PG_NODE_WG_HOST_ROUTING", true),
		WGNATOutputInterface: GetEnv("PG_NODE_WG_NAT_OUTPUT_INTERFACE", ""),
		WGNATEgressOnly:      GetEnvAsBool("PG_NODE_WG_NAT_EGRESS_ONLY", true),
		WGNATDisable:         GetEnvAsBool("PG_NODE_WG_NAT_DISABLE", false),
		WGRouteTable:         GetEnv("PG_NODE_WG_ROUTE_TABLE", ""),
		WGRouteOutInterface:  GetEnv("PG_NODE_WG_ROUTE_OUT_INTERFACE", ""),
	}

	if cfg.LogBufferSize <= 0 {
		log.Printf("[Warning] LOG_BUFFER_SIZE must be greater than 0, got %d. Falling back to 1.", cfg.LogBufferSize)
		cfg.LogBufferSize = 1
	}

	// The API key is the node's only authentication. A missing, malformed or all-zero key
	// would leave the node accepting the all-zero UUID, so Load reports it as an error
	// (main exits). cfg is still returned complete for NewTestConfig, which sets its own key.
	var apiKeyErr error
	if GetEnv("API_KEY", "") == "" {
		apiKeyErr = errors.New("API_KEY is not set")
	} else {
		cfg.ApiKey, apiKeyErr = GetEnvAsUUID("API_KEY")
	}
	if apiKeyErr == nil && cfg.ApiKey == uuid.Nil {
		apiKeyErr = errors.New("must not be the all-zero UUID")
	}
	if apiKeyErr != nil {
		apiKeyErr = fmt.Errorf("invalid API_KEY: %w", apiKeyErr)
	}

	var tlsErr error
	if value, exists := os.LookupEnv("TLS_ENABLED"); exists {
		cfg.TLSEnabled, tlsErr = strconv.ParseBool(value)
		if tlsErr != nil {
			tlsErr = fmt.Errorf("invalid TLS_ENABLED %q: expected a boolean", value)
		}
	}
	defaultHost := "0.0.0.0"
	if !cfg.TLSEnabled {
		defaultHost = "127.0.0.1"
	}
	host := GetEnv("NODE_HOST", defaultHost)
	var hostErr error
	if cfg.TLSEnabled {
		cfg.NodeHost = parseNodeHost(host)
	} else {
		cfg.NodeHost, hostErr = PrivateBackendHost(host)
	}
	return cfg, errors.Join(apiKeyErr, tlsErr, hostErr)
}

// PrivateBackendHost permits only literal loopback, RFC1918 and IPv6 ULA
// addresses. Do not resolve hostnames: DNS changes must never expose a backend.
func PrivateBackendHost(value string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err == nil && addr.Zone() == "" {
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsPrivate() {
			return addr.String(), nil
		}
	}
	return "", fmt.Errorf("TLS_ENABLED=false requires NODE_HOST to be a loopback, RFC1918 IPv4 or IPv6 unique-local address; got %q", value)
}

// parseNodeHost returns the IPv4 or IPv6 address to listen on; "localhost" means 127.0.0.1.
// A scoped IPv6 address (fe80::1%eth0) is accepted too, since net.Listen takes the zone.
// Any other value keeps the old fallback to 127.0.0.1, so a node that started before still
// starts, but it is logged as an error: the panel usually cannot reach a loopback-only node.
func parseNodeHost(value string) string {
	host := strings.TrimSpace(value)
	if strings.EqualFold(host, "localhost") {
		return "127.0.0.1"
	}
	if _, err := netip.ParseAddr(host); err != nil {
		log.Printf("[Error] NODE_HOST %q is not an IP address (for example 0.0.0.0 or ::). Falling back to 127.0.0.1: only clients on this host can reach the node.", value)
		return "127.0.0.1"
	}
	return host
}

// NewTestConfig creates a config for testing
func NewTestConfig(generatedConfigPath string, key uuid.UUID) *Config {
	cfg, _ := Load()
	cfg.GeneratedConfigPath = generatedConfigPath
	cfg.ApiKey = key
	return cfg
}

func GetEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
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
