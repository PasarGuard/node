package openvpn

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
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
		"server": "10.8.0.0/24",
		"dns": ["1.1.1.1", "1.0.0.1"]
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
	text := renderForTest(t, `{"port": 1194, "dns": ["1.1.1.1"]}`)
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
	// The agreed panel schema has no redirect-gateway key, so the core must not
	// silently decide to route a client's whole traffic.
	if strings.Contains(text, "redirect-gateway") {
		t.Error("rendered config pushes redirect-gateway without a panel key to ask for it")
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

// The panel's schema is the contract: what it must reject, and what it must
// default when a key is simply absent.
func TestConfigValidation(t *testing.T) {
	bad := map[string]string{
		"port is required":    `{}`,
		"port out of range":   `{"port": 70000}`,
		"port zero":           `{"port": -1}`,
		"bad protocol":        `{"port": 1194, "protocol": "sctp"}`,
		"host bits set":       `{"port": 1194, "server": "10.8.0.5/24"}`,
		"not a CIDR":          `{"port": 1194, "server": "10.8.0.0"}`,
		"ipv6 pool refused":   `{"port": 1194, "server": "fd00::/64"}`,
		"pool too small":      `{"port": 1194, "server": "10.8.0.0/31"}`,
		"bad dns":             `{"port": 1194, "dns": ["not-an-ip"]}`,
		"partial PKI":         `{"port": 1194, "ca": "-----BEGIN CERTIFICATE-----\n...\n"}`,
		"tls_crypt not a key": `{"port": 1194, "tls_crypt": "somerandomstring"}`,
		"not json at all":     `{port}`,
	}
	for name, cfg := range bad {
		if _, err := NewConfig(cfg, nil); err == nil {
			t.Errorf("%s: NewConfig(%s) succeeded, want an error", name, cfg)
		}
	}

	// Defaults: protocol udp, the documented pool, DNS optional.
	c, err := NewConfig(`{"port": 21194}`, nil)
	if err != nil {
		t.Fatalf("minimal config: %v", err)
	}
	if c.Protocol != defaultProtocol || c.Server != defaultServerCIDR {
		t.Errorf("defaults not applied: protocol=%q server=%q", c.Protocol, c.Server)
	}
	if c.Network() != "10.8.0.0" || c.Netmask() != "255.255.255.0" {
		t.Errorf("pool split wrong: %s/%s", c.Network(), c.Netmask())
	}
	// An empty config is not a silent default: port is the one required key.
	if _, err := NewConfig("", nil); err == nil || !strings.Contains(err.Error(), "port is required") {
		t.Errorf("empty config: err = %v, want port is required", err)
	}
}

// The PKI is created once, is private, and the leaf actually verifies against
// the CA — the third part is what stops a silently-broken CA from reaching a
// client that then dies with a TLS error nobody can read.
func TestPKIIsGeneratedOnceAndVerifies(t *testing.T) {
	dir := t.TempDir()
	if err := ensurePKI(dir, &Config{}); err != nil {
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
	if err := ensurePKI(dir, &Config{}); err != nil {
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

// An operator-pasted set is authoritative: it lands on disk, it is not
// regenerated, and no ca.key is invented beside it.
func TestSuppliedPKIIsWrittenAndNeverRegenerated(t *testing.T) {
	src := t.TempDir()
	if err := ensurePKI(src, &Config{}); err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(src, caCertFile))
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(filepath.Join(src, serverCert))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(src, serverKey))
	if err != nil {
		t.Fatal(err)
	}
	key, err := staticKey()
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := NewConfig(fmtConfig(1194, string(caPEM), string(certPEM), string(keyPEM), string(key)), nil)
	if err != nil {
		t.Fatalf("config with pasted PKI: %v", err)
	}
	dst := t.TempDir()
	if err := ensurePKI(dst, cfg); err != nil {
		t.Fatalf("ensurePKI with supplied PKI: %v", err)
	}
	for name, want := range map[string][]byte{
		caCertFile: caPEM, serverCert: certPEM, serverKey: keyPEM, tlsCryptFile: key,
	} {
		got, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.TrimRight(string(got), "\n") != strings.TrimRight(string(want), "\n") {
			t.Errorf("%s was not written verbatim from the config", name)
		}
	}
	// No signing key is invented: the paste did not carry one, so there is none.
	if _, err := os.Stat(filepath.Join(dst, caKeyFile)); !os.IsNotExist(err) {
		t.Errorf("a ca.key appeared beside an operator-pasted set: %v", err)
	}
}

// A server certificate signed by some other CA is refused at start rather than
// at a client's first handshake.
func TestSuppliedPKIMismatchIsRefused(t *testing.T) {
	a := t.TempDir()
	if err := ensurePKI(a, &Config{}); err != nil {
		t.Fatal(err)
	}
	b := t.TempDir()
	if err := ensurePKI(b, &Config{}); err != nil {
		t.Fatal(err)
	}
	read := func(dir, name string) string {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	// b's certificate with a's CA: different issuers.
	_, err := NewConfig(fmtConfig(1194, read(a, caCertFile), read(b, serverCert), read(b, serverKey), ""), nil)
	if err != nil {
		t.Fatalf("config parsed: %v", err)
	}
	err = ensurePKI(t.TempDir(), mustParse(t, fmtConfig(1194, read(a, caCertFile), read(b, serverCert), read(b, serverKey), "")))
	if err == nil || !strings.Contains(err.Error(), "not signed by") {
		t.Errorf("mismatched paste accepted: %v", err)
	}
}

// fmtConfig builds the JSON the panel sends when an operator pasted a
// certificate set. json.Marshal because the PEM bodies are multi-line.
func fmtConfig(port int, ca, cert, key, tlsCrypt string) string {
	m := map[string]any{"port": port}
	if ca != "" {
		m["ca"], m["cert"], m["key"] = ca, cert, key
	}
	if tlsCrypt != "" {
		m["tls_crypt"] = tlsCrypt
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err) // map[string]any of strings cannot fail to marshal
	}
	return string(b)
}

func mustParse(t *testing.T, cfg string) *Config {
	t.Helper()
	c, err := NewConfig(cfg, nil)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	return c
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
		return "", errEmptyPEM
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

var errEmptyPEM = errors.New("empty PEM block")

func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }

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
