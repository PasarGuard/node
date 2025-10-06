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
		expectInError bool // true if should be in error log, false if in access log
	}{
		{
			name:          "Access log - TCP connection",
			logMessage:    "2025/10/06 11:28:38.624743 from 2.187.120.79:48394 accepted tcp:www.gstatic.com:443 [REALITY_GRPC_1 -> DIRECT] email: 7.Family",
			expectInError: false,
		},
		{
			name:          "Access log - UDP connection",
			logMessage:    "2025/10/06 11:28:38.624743 from 5.117.22.146:16425 accepted udp:dns.google.com:53 [REALITY_GRPC_1 -> DIRECT] email: 1.Myself",
			expectInError: false,
		},
		{
			name:          "Error log - Debug level",
			logMessage:    "2025/10/06 11:28:34.717774 [Debug] app/log: Logger started",
			expectInError: true,
		},
		{
			name:          "Error log - Info level",
			logMessage:    "2025/10/06 11:28:38.623664 [Info] [673738803] proxy/vless/inbound: firstLen = 983",
			expectInError: true,
		},
		{
			name:          "Error log - Warning level",
			logMessage:    "2024/01/15 10:30:45.654321 [Warning] connection timeout",
			expectInError: true,
		},
		{
			name:          "Error log - Error level",
			logMessage:    "2024/01/15 10:30:45.123456 [Error] failed to connect to server",
			expectInError: true,
		},
		{
			name:          "Error log - No level specified",
			logMessage:    "some random log without level",
			expectInError: true,
		},
		{
			name:          "Error log - Unknown level",
			logMessage:    "2024/01/15 10:30:45.901234 [Unknown] some message",
			expectInError: true,
		},
		{
			name:          "Error log - Router matcher",
			logMessage:    "2025/10/06 11:28:34.717852 [Debug] app/router: MphDomainMatcher is enabled for 24 domain rule(s)",
			expectInError: true,
		},
		{
			name:          "Error log - Stats counter",
			logMessage:    "2025/10/06 11:28:34.723790 [Debug] app/stats: create new counter outbound>>>DIRECT>>>traffic>>>uplink",
			expectInError: true,
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
