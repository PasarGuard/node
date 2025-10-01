package config

import (
	"log"
	"os"
	"regexp"
	"strconv"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Printf("[Warning] Failed to load env file, if you're using 'Docker' and you set 'environment' or 'env_file' variable, don't worry, everything is fine. Error: %v", err)
	}

	ServicePort = GetEnvAsInt("SERVICE_PORT", 62050)
	XrayExecutablePath = GetEnv("XRAY_EXECUTABLE_PATH", "/usr/local/bin/xray")
	XrayAssetsPath = GetEnv("XRAY_ASSETS_PATH", "/usr/local/share/xray")
	SslCertFile = GetEnv("SSL_CERT_FILE", "/var/lib/pg-node/certs/ssl_cert.pem")
	SslKeyFile = GetEnv("SSL_KEY_FILE", "/var/lib/pg-node/certs/ssl_key.pem")
	ApiKey, err = GetEnvAsUUID("API_KEY")
	if err != nil {
		log.Printf("[Error] Faild to load API Key, error: %v", err)
	}
	GeneratedConfigPath = GetEnv("GENERATED_CONFIG_PATH", "/var/lib/pg-node/generated/")
	ServiceProtocol = GetEnv("SERVICE_PROTOCOL", "grpc")
	Debug = GetEnvAsBool("DEBUG", false)
	nodeHostStr := GetEnv("NODE_HOST", "0.0.0.0")

	ipPattern := `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`

	// Compile the regular expression
	re := regexp.MustCompile(ipPattern)

	// Check if WEBAPP_HOST matches the IP address pattern
	if re.MatchString(nodeHostStr) {
		NodeHost = nodeHostStr
	} else {
		log.Println(nodeHostStr, " is not a valid IP address.\n WEBAPP_HOST will be set to 127.0.0.1")
		NodeHost = "127.0.0.1"
	}

	LogBufferSize = GetEnvAsInt("LOG_BUFFER_SIZE", 1000)
}

// Warning: only use in tests
func SetEnvForTest(generatedConfigPath string, key uuid.UUID) {
	GeneratedConfigPath = generatedConfigPath
	ApiKey = key
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

var (
	ServicePort         int
	NodeHost            string
	XrayExecutablePath  string
	XrayAssetsPath      string
	SslCertFile         string
	SslKeyFile          string
	ApiKey              uuid.UUID
	ServiceProtocol     string
	Debug               bool
	GeneratedConfigPath string
	LogBufferSize       int
)
