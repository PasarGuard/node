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
		{
			name:          "Error log - from/accepted fragments without access pattern",
			logMessage:    "[Warning] rejected request from 10.0.0.1:443: connection not accepted by destination",
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

// TestIsAccessLogEntry checks accepted and rejected entries, including the two spaces Xray writes
// after "rejected", and that error lines mentioning "from" or "rejected" are not access entries.
func TestIsAccessLogEntry(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{line: "2026/11/04 07:27:52.690940 from 203.0.113.7:60253 accepted tcp:example.com:443 [in -> out] email: user1", want: true},
		{line: "2026/11/04 07:27:52.692433 from tcp:203.0.113.8:8436 accepted udp:1.1.1.1:53 [in >> direct] email: user2", want: true},
		// Rejected entries have no destination, so Xray writes two spaces after "rejected".
		{line: "2026/11/04 07:30:41.120004 from 198.51.100.4:54596 rejected  proxy/vless/encoding: invalid request user id: 00000000-0000-0000-0000-000000000000", want: true},
		{line: "from 198.51.100.4:54596 rejected  proxy/vless/encoding: invalid request user id", want: true},
		{line: "2026/11/04 07:27:53.000001 [Warning] rejected request from 10.0.0.1:443: connection not accepted by destination", want: false},
		{line: "Failed to start: app/proxyman/inbound: failed to listen TCP on 443", want: false},
		{line: "", want: false},
	}

	for _, tt := range tests {
		if got := isAccessLogEntry(tt.line); got != tt.want {
			t.Fatalf("isAccessLogEntry(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}
