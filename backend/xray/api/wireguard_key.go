package api

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// WireguardKeyToHex normalizes a WireGuard key from base64 (panel) or hex (Xray API) to hex.
func WireguardKeyToHex(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("empty wireguard key")
	}

	if len(key) == 64 {
		if _, err := hex.DecodeString(key); err == nil {
			return key, nil
		}
	}

	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("invalid wireguard key encoding: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("invalid wireguard key length: %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
