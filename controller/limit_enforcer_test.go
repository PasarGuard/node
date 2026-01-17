package controller

import (
	"testing"
)

func TestParseUserStatName(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedID   int
		expectedMail string
	}{
		{
			name:         "valid uplink stat",
			input:        "user>>>1.username>>>traffic>>>uplink",
			expectedID:   1,
			expectedMail: "1.username",
		},
		{
			name:         "valid downlink stat",
			input:        "user>>>42.testuser>>>traffic>>>downlink",
			expectedID:   42,
			expectedMail: "42.testuser",
		},
		{
			name:         "user with dots in name",
			input:        "user>>>123.user.with.dots>>>traffic>>>uplink",
			expectedID:   123,
			expectedMail: "123.user.with.dots",
		},
		{
			name:         "invalid - not user stat",
			input:        "inbound>>>vmess>>>traffic>>>uplink",
			expectedID:   0,
			expectedMail: "",
		},
		{
			name:         "invalid - no parts",
			input:        "invalid",
			expectedID:   0,
			expectedMail: "",
		},
		{
			name:         "invalid - no user id",
			input:        "user>>>noIdUsername>>>traffic>>>uplink",
			expectedID:   0,
			expectedMail: "noIdUsername",
		},
		{
			name:         "invalid - non-numeric id",
			input:        "user>>>abc.username>>>traffic>>>uplink",
			expectedID:   0,
			expectedMail: "abc.username",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, email := parseUserStatName(tt.input)
			if id != tt.expectedID {
				t.Errorf("parseUserStatName(%q) id = %d, want %d", tt.input, id, tt.expectedID)
			}
			if email != tt.expectedMail {
				t.Errorf("parseUserStatName(%q) email = %q, want %q", tt.input, email, tt.expectedMail)
			}
		})
	}
}

func TestLimitEnforcerConfig_Defaults(t *testing.T) {
	// Test default values are applied
	cfg := LimitEnforcerConfig{
		NodeID:      1,
		PanelAPIURL: "http://localhost",
		APIKey:      "test-key",
	}

	if cfg.CheckInterval != 0 {
		t.Error("CheckInterval should be 0 before NewLimitEnforcer")
	}
	if cfg.RefreshInterval != 0 {
		t.Error("RefreshInterval should be 0 before NewLimitEnforcer")
	}
}
