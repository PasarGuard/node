package config

import (
	"log"
	"os"
	"regexp"
	"strconv"

	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Failed to load env file , Error: %v", err)
	}

	ServicePort = GetEnvAsInt("SERVICE_PORT", 62050)
	XrayExecutablePath = GetEnv("XRAY_EXECUTABLE_PATH", "/usr/local/bin/xray")
	XrayAssetsPath = GetEnv("XRAY_ASSETS_PATH", "/usr/local/share/xray")
	SslCertFile = GetEnv("SSL_CERT_FILE", "/var/lib/marzban-node/ssl_cert.pem")
	SslKeyFile = GetEnv("SSL_KEY_FILE", "/var/lib/marzban-node/ssl_key.pem")
	SslClientCertFile = GetEnv("SSL_CLIENT_CERT_FILE", "/var/lib/marzban-node/ssl_client_cert_file.pem")
	GeneratedConfigPath = GetEnv("GENERATED_CONFIG_PATH", "/var/lib/marzban-node/generated_config-debug.json")
	MaxLogPerRequest = GetEnvAsInt("MAX_LOG_PER_REQUEST", 1000)
	Debug = GetEnvAsBool("DEBUG", false)
	nodeHostStr := GetEnv("NODE_HOST", "0.0.0.0")

	ipPattern := `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`

	// Compile the regular expression
	re := regexp.MustCompile(ipPattern)

	// Check if WEBAPP_HOST matches the IP address pattern
	if re.MatchString(nodeHostStr) {
		NodeHost = nodeHostStr
	} else {
		log.Println(nodeHostStr, " is not a valid IP address.\n WEBAPP_HOST will be set to 0.0.0.0")
		NodeHost = "0.0.0.0"
	}
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

var (
	ServicePort         int
	NodeHost            string
	XrayExecutablePath  string
	XrayAssetsPath      string
	SslCertFile         string
	SslKeyFile          string
	SslClientCertFile   string
	MaxLogPerRequest    int
	Debug               bool
	GeneratedConfigPath string
)
