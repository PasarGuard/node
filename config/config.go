package config

import (
	"github.com/joho/godotenv"
	log "marzban-node/logger"
	"os"
	"strconv"
)

func InitConfig() {
	err := godotenv.Load()
	if err != nil {
		log.ErrorLog("Failed to load env file , Error: ", err)
	}

	ServicePort = GetEnvAsInt("SERVICE_PORT", 62050)
	XrayApiPort = GetEnvAsInt("XRAY_API_PORT", 62051)
	NodeHost = GetEnv("NODE_HOST", "0.0.0.0")
	XrayExecutablePath = GetEnv("XRAY_EXECUTABLE_PATH", "/usr/local/bin/xray")
	XrayAssetsPath = GetEnv("XRAY_ASSETS_PATH", "/usr/local/share/xray")
	SslCertFile = GetEnv("SSL_CERT_FILE", "/var/lib/marzban-node/ssl_cert.pem")
	SslKeyFile = GetEnv("SSL_KEY_FILE", "/var/lib/marzban-node/ssl_key.pem")
	SslClientCertFile = GetEnv("SSL_CLIENT_CERT_FILE", "/var/lib/marzban-node/ssl_client_cert_file.pem")
	Debug = GetEnvAsBool("DEBUG", false)

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
	ServicePort        int
	XrayApiPort        int
	NodeHost           string
	XrayExecutablePath string
	XrayAssetsPath     string
	SslCertFile        string
	SslKeyFile         string
	SslClientCertFile  string
	Debug              bool
)
