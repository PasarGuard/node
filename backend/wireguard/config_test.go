package wireguard

import (
	"net"
	"testing"
)

func TestConfigInterfaceNetworks(t *testing.T) {
	cfg := &Config{Address: []string{" 10.8.0.1/24 ", ""}}
	nets := cfg.InterfaceNetworks()
	if len(nets) != 1 {
		t.Fatalf("expected 1 network, got %d", len(nets))
	}
	if nets[0].String() != "10.8.0.0/24" {
		t.Fatalf("unexpected network: %s", nets[0].String())
	}
	_, ipn, _ := net.ParseCIDR("10.8.0.5/32")
	if !peerIPAllowedOnInterface(ipn, nets) {
		t.Fatal("expected 10.8.0.5/32 to be allowed under 10.8.0.0/24")
	}
	_, wrong, _ := net.ParseCIDR("10.0.0.2/32")
	if peerIPAllowedOnInterface(wrong, nets) {
		t.Fatal("expected 10.0.0.2/32 to be rejected under 10.8.0.0/24")
	}
}

func TestNewWireGuardConfig(t *testing.T) {
	configJSON := `{
		"interface_name": "wg0",
		"private_key": "cGVlckNvbmZpZ0VudHJ5AA==",
		"listen_port": 51820,
		"address": ["10.0.0.1/16"]
	}`

	config, err := NewConfig(configJSON)
	if err != nil {
		t.Fatalf("NewConfig failed: %v", err)
	}

	if config.InterfaceName != "wg0" {
		t.Errorf("Expected interface_name 'wg0', got: %s", config.InterfaceName)
	}

	if config.ListenPort != 51820 {
		t.Errorf("Expected listen_port 51820, got: %d", config.ListenPort)
	}

	if len(config.Address) != 1 || config.Address[0] != "10.0.0.1/16" {
		t.Errorf("Expected address '10.0.0.1/16', got: %v", config.Address)
	}

}

func TestNewWireGuardConfigDefaults(t *testing.T) {
	configJSON := `{}`

	config, err := NewConfig(configJSON)
	if err != nil {
		t.Fatalf("NewConfig failed: %v", err)
	}

	if config.InterfaceName != "wg0" {
		t.Errorf("Expected default interface_name 'wg0', got: %s", config.InterfaceName)
	}

	if config.ListenPort != 51820 {
		t.Errorf("Expected default listen_port 51820, got: %d", config.ListenPort)
	}
}

func TestNewWireGuardConfigInvalidJSON(t *testing.T) {
	configJSON := `{invalid json}`

	_, err := NewConfig(configJSON)
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}
}

func TestGenerateKeyPair(t *testing.T) {
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if privKey == "" {
		t.Error("Expected non-empty private key")
	}

	if pubKey == "" {
		t.Error("Expected non-empty public key")
	}

	// Keys should be base64 encoded (44 characters for WireGuard keys)
	if len(privKey) != 44 {
		t.Errorf("Expected private key length 44, got: %d", len(privKey))
	}

	if len(pubKey) != 44 {
		t.Errorf("Expected public key length 44, got: %d", len(pubKey))
	}
}

func TestGetPrivateKey(t *testing.T) {
	// Generate a valid key first
	privKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	config := &Config{
		PrivateKey: privKey,
	}

	key, err := config.GetPrivateKey()
	if err != nil {
		t.Fatalf("GetPrivateKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32 bytes, got: %d", len(key))
	}
}

func TestGetPrivateKeyEmpty(t *testing.T) {
	config := &Config{
		PrivateKey: "",
	}

	_, err := config.GetPrivateKey()
	if err == nil {
		t.Fatal("Expected GetPrivateKey to fail when private key is empty")
	}

	if err.Error() != "private key is empty" {
		t.Fatalf("Expected error 'private key is empty', got: %v", err)
	}
}
