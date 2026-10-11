package hysteria

import (
	"bytes"
	"testing"
)

// The panel stores its own `pasarguard` block in the core config (origin-cert
// paste -> derived client pin). The binary must never see it: hysteria decodes
// the config strictly, and an unknown top-level key is a start failure waiting
// for an upstream version bump. ToBytes is the only place the config becomes a
// file, so it is the only place the strip needs to exist.
func TestToBytesStripsPanelOnlyPasarguardBlock(t *testing.T) {
	const source = `{"listen":"127.0.0.1:443","pasarguard":{"originCert":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n","pinSHA256":"aa","certPublicTrusted":false}}`

	cfg, err := NewConfig(source, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	buf, err := cfg.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes: %v", err)
	}
	if bytes.Contains(buf, []byte("pasarguard")) {
		t.Fatalf("ToBytes leaked the panel-only pasarguard block:\n%s", buf)
	}
	if !bytes.Contains(buf, []byte("127.0.0.1:443")) {
		t.Fatalf("ToBytes dropped real config keys:\n%s", buf)
	}

	// and a config without the block is byte-for-byte untouched
	plain, err := NewConfig(`{"listen":"127.0.0.1:443"}`, nil)
	if err != nil {
		t.Fatalf("NewConfig(plain): %v", err)
	}
	buf, err = plain.ToBytes()
	if err != nil {
		t.Fatalf("ToBytes(plain): %v", err)
	}
	if !bytes.Contains(buf, []byte(`"listen": "127.0.0.1:443"`)) {
		t.Fatalf("plain config changed shape:\n%s", buf)
	}
}
