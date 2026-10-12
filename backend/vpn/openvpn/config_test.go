package openvpn

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/server.conf from the current renderer")

// goldenOptions pins every absolute path the renderer embeds, so the golden
// file is byte-stable across machines.
func goldenOptions() RenderOptions {
	return RenderOptions{
		AuthExecutable:         "/usr/local/bin/pg-ovpn-auth",
		ManagementSocket:       "/var/lib/pg-node/generated/core-1/mgmt.sock",
		ManagementPasswordFile: "/var/lib/pg-node/generated/core-1/mgmt.pw",
		ClientConfigDir:        "ccd",
	}
}

func renderForTest(t *testing.T, jsonConfig string) string {
	t.Helper()
	c, err := NewConfig(jsonConfig, nil)
	if err != nil {
		t.Fatalf("NewConfig(%s): %v", jsonConfig, err)
	}
	return c.Render(goldenOptions())
}

func TestRenderServerConfigGolden(t *testing.T) {
	got := renderForTest(t, `{
		"port": 1194,
		"protocol": "udp",
		"network": "10.8.0.0",
		"netmask": "255.255.255.0",
		"dns": ["1.1.1.1", "1.0.0.1"],
		"redirect_gateway": true
	}`)

	golden := filepath.Join("testdata", "server.conf")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading %s (run: go test ./backend/vpn/openvpn -run Golden -update): %v", golden, err)
	}
	if got != string(want) {
		t.Errorf("rendered server.conf differs from the golden file.\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}
}

// The golden file catches an unintended change; these catch a change that is
// wrong on purpose — a refreshed golden must not be able to drop them.
func TestRenderCarriesTheSecurityPosture(t *testing.T) {
	text := renderForTest(t, `{"redirect_gateway": true, "dns": ["1.1.1.1"]}`)
	for _, want := range []string{
		"tls-version-min 1.2",
		"data-ciphers AES-256-GCM:CHACHA20-POLY1305",
		"tls-crypt tls-crypt.key",
		"allow-compression no",
		"verify-client-cert none",
		"username-as-common-name",
		"topology subnet",
		"client-config-dir ccd",
		"ccd-exclusive",
		"script-security 2",
		"auth-user-pass-verify /usr/local/bin/pg-ovpn-auth via-file",
		"management /var/lib/pg-node/generated/core-1/mgmt.sock unix /var/lib/pg-node/generated/core-1/mgmt.pw",
		"server 10.8.0.0 255.255.255.0",
		"port 1194",
		"proto udp",
		"push \"dhcp-option DNS 1.1.1.1\"",
		"push \"redirect-gateway def1 bypass-dhcp\"",
		"dh none",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered config is missing %q\n%s", want, text)
		}
	}
	// No compression, in any of the forms upstream accepts. Compression is the
	// VORBLEACH-class weakness and there is no configuration where it is wanted.
	for _, forbidden := range []string{"comp-lzo", "\ncompress ", "\ncompress\n", "comp-noadapt"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("rendered config enables compression (%q)\n%s", forbidden, text)
		}
	}
	// `dh none` must be paired with an ECDHE-only control-channel list, or the
	// DHE suites it leaves on the table have no group to run on.
	if !strings.Contains(text, "tls-cipher TLS-ECDHE-") {
		t.Error("dh none is rendered without an ECDHE-only tls-cipher list")
	}
	if strings.Contains(text, "\nuser ") || strings.Contains(text, "\ngroup ") {
		t.Error("rendered config drops privileges: the node writes CCD files as its own user at runtime")
	}
}

func TestRenderTCPDropsExitNotify(t *testing.T) {
	text := renderForTest(t, `{"protocol": "tcp", "port": 443}`)
	if !strings.Contains(text, "proto tcp-server") {
		t.Errorf("want proto tcp-server, got:\n%s", text)
	}
	if strings.Contains(text, "explicit-exit-notify") {
		t.Errorf("explicit-exit-notify is UDP-only:\n%s", text)
	}
}

func TestConfigValidation(t *testing.T) {
	bad := map[string]string{
		"host bits set":     `{"network": "10.8.0.5", "netmask": "255.255.255.0"}`,
		"bad protocol":      `{"protocol": "sctp"}`,
		"port out of range": `{"port": 70000}`,
		"bad dns":           `{"dns": ["not-an-ip"]}`,
		"pool too small":    `{"network": "10.8.0.0", "netmask": "255.255.255.254"}`,
		"not json at all":   `{port}`,
		"ipv6 pool refused": `{"network": "fd00::", "netmask": "ffff::"}`,
	}
	for name, cfg := range bad {
		if _, err := NewConfig(cfg, nil); err == nil {
			t.Errorf("%s: NewConfig(%s) succeeded, want an error", name, cfg)
		}
	}
	// An absent config is the documented default, not a failure.
	c, err := NewConfig("", nil)
	if err != nil {
		t.Fatalf("empty config: %v", err)
	}
	if c.Port != defaultPort || c.Protocol != defaultProtocol || c.Network != defaultNetwork {
		t.Errorf("defaults not applied: %+v", c)
	}
}

// The PKI is created once, is private, and the leaf actually verifies against
// the CA — the third part is what stops a silently-broken CA from reaching a
// client that then dies with a TLS error nobody can read.
func TestPKIIsGeneratedOnceAndVerifies(t *testing.T) {
	dir := t.TempDir()
	if err := ensurePKI(dir); err != nil {
		t.Fatalf("ensurePKI: %v", err)
	}
	first := map[string][]byte{}
	for _, name := range []string{caCertFile, caKeyFile, serverCert, serverKey, tlsCryptFile} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		first[name] = data
		if runtime.GOOS != "windows" {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if mode := info.Mode().Perm(); mode != 0o600 {
				t.Errorf("%s mode = %o, want 600", name, mode)
			}
		}
	}
	if err := ensurePKI(dir); err != nil {
		t.Fatalf("second ensurePKI: %v", err)
	}
	for name, want := range first {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s was rewritten on a second ensurePKI — a restart would hand clients a CA the server no longer trusts", name)
		}
	}

	if _, err := verifyChain(dir); err != nil {
		t.Errorf("server certificate does not verify against the CA: %v", err)
	}
}

// The tls-crypt key must be exactly what `openvpn --genkey secret` writes, or
// the server refuses it and every client handshake fails.
func TestStaticKeyMatchesTheOpenVPNFormat(t *testing.T) {
	key, err := staticKey()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(key), "\n"), "\n")
	if lines[0] != "#" || !strings.HasPrefix(lines[1], "# ") {
		t.Fatalf("missing the header comment:\n%s", key)
	}
	if lines[3] != "-----BEGIN OpenVPN Static key V1-----" {
		t.Fatalf("bad BEGIN marker: %q", lines[3])
	}
	if lines[len(lines)-1] != "-----END OpenVPN Static key V1-----" {
		t.Fatalf("bad END marker: %q", lines[len(lines)-1])
	}
	body := lines[4 : len(lines)-1]
	if len(body) != 16 {
		t.Fatalf("got %d hex rows, want 16 (256 bytes / 2048 bits)", len(body))
	}
	for i, row := range body {
		if len(row) != 32 {
			t.Fatalf("row %d has %d hex digits, want 32", i, len(row))
		}
		if _, err := decodeHex(row); err != nil {
			t.Fatalf("row %d is not hex: %v", i, err)
		}
	}
}

// verifyChain proves the leaf the server will present is signed by the CA the
// clients will be handed.
func verifyChain(dir string) (string, error) {
	caPEM, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return "", err
	}
	leafPEM, err := os.ReadFile(filepath.Join(dir, serverCert))
	if err != nil {
		return "", err
	}
	caBlock, _ := pem.Decode(caPEM)
	leafBlock, _ := pem.Decode(leafPEM)
	if caBlock == nil || leafBlock == nil {
		return "", err
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return "", err
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return "", err
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return "", err
	}
	return leaf.Subject.CommonName, nil
}

func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }
