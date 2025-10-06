package xray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	nodeLogger "github.com/pasarguard/node/logger"
)

func TestDetectLogType(t *testing.T) {
	tests := []struct {
		name          string
		logMessage    string
		expectedLevel nodeLogger.LogLevel
		expectInError bool // true if should be in error log, false if in access log
	}{
		{
			name:          "Error log",
			logMessage:    "2024/01/15 10:30:45.123456 [Error] failed to connect to server",
			expectedLevel: nodeLogger.LogError,
			expectInError: true,
		},
		{
			name:          "Warning log",
			logMessage:    "2024/01/15 10:30:45.654321 [Warning] connection timeout",
			expectedLevel: nodeLogger.LogWarning,
			expectInError: false,
		},
		{
			name:          "Info log",
			logMessage:    "2024/01/15 10:30:45.789012 [Info] server started successfully",
			expectedLevel: nodeLogger.LogInfo,
			expectInError: false,
		},
		{
			name:          "Debug log",
			logMessage:    "2024/01/15 10:30:45.345678 [Debug] processing request",
			expectedLevel: nodeLogger.LogDebug,
			expectInError: false,
		},
		{
			name:          "No level specified",
			logMessage:    "some random log without level",
			expectedLevel: nodeLogger.LogDebug,
			expectInError: false,
		},
		{
			name:          "Unknown level",
			logMessage:    "2024/01/15 10:30:45.901234 [Unknown] some message",
			expectedLevel: nodeLogger.LogDebug,
			expectInError: false,
		},
		{
			name:          "Case insensitive - ERROR",
			logMessage:    "2024/01/15 10:30:45.567890 [ERROR] critical failure",
			expectedLevel: nodeLogger.LogError,
			expectInError: true,
		},
		{
			name:          "Case insensitive - warning",
			logMessage:    "2024/01/15 10:30:45.234567 [warning] deprecated API used",
			expectedLevel: nodeLogger.LogWarning,
			expectInError: false,
		},
		{
			name:          "Real world Info log with ID",
			logMessage:    "2025/10/06 09:07:45.488514 [Info] [1562064288] app/proxyman/inbound: connection ends > proxy/vmess/encoding: failed to read request header > EOF",
			expectedLevel: nodeLogger.LogInfo,
			expectInError: false,
		},
		{
			name:          "Real world log with domain sniffing",
			logMessage:    "2025/10/04 14:38:31.673612 [Info] [798316497] app/dispatcher: sniffed domain: i.instagram.com",
			expectedLevel: nodeLogger.LogInfo,
			expectInError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary log files
			tmpDir := t.TempDir()
			accessLog := filepath.Join(tmpDir, "access.log")
			errorLog := filepath.Join(tmpDir, "error.log")

			logger := nodeLogger.New(false)
			if err := logger.SetLogFile(accessLog, errorLog); err != nil {
				t.Fatalf("Failed to set log files: %v", err)
			}
			defer logger.Close()

			core := &Core{
				logger: logger,
			}

			core.detectLogType(tt.logMessage)

			// Read the appropriate log file
			var logContent []byte
			var err error
			if tt.expectInError {
				logContent, err = os.ReadFile(errorLog)
			} else {
				logContent, err = os.ReadFile(accessLog)
			}

			if err != nil {
				t.Fatalf("Failed to read log file: %v", err)
			}

			// Verify the complete message is logged
			if !strings.Contains(string(logContent), tt.logMessage) {
				t.Errorf("Log file does not contain the expected message.\nExpected: %v\nGot: %v", tt.logMessage, string(logContent))
			}
		})
	}
}
