package hysteria

// Cloudflare-Origin-style certificate modes against the pinned v2.13.0.
//
// A Cloudflare Origin cert is signed by a CA that is NOT in any client's
// trust store, so it behaves exactly like the CA-signed leaf these tests
// generate: chain verification fails by default, `insecure` skips it, and
// `pinSHA256` (hex of the leaf) pins it. The server runs with the default
// `sniGuard: dns-san`, the mode a shipped hysteria core gets.
//
// Every case is one test, one server, one real client -- a green run with no
// traffic is impossible, and every negative control asserts bytes == 0.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pasarguard/node/common"
)

// writeCAAndLeaf produces a two-level chain: a throwaway CA and a leaf whose
// DNS SANs are exactly ("hysteria.test", "*.wild.test"). The leaf key type is
// RSA-2048 (an ECDSA P-256 leaf works too -- follow-up 2 retired the old
// ECDSA claim -- RSA keeps the chain boring).
func writeCAAndLeaf(t *testing.T, dir string) (caPath, certPath, keyPath string) {
	t.Helper()
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("openssl not on PATH; cannot generate the TLS material: %v", err)
	}
	env := append(os.Environ(), "MSYS_NO_PATHCONV=1") // Git-Bash mangles /CN=... args
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(openssl, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
	}

	caPath = filepath.Join(dir, "ca.pem")
	caKey := filepath.Join(dir, "ca.key")
	run("req", "-x509", "-newkey", "rsa:2048", "-keyout", caKey, "-out", caPath,
		"-days", "2", "-nodes", "-subj", "/CN=PasarGuard Test Origin CA")

	certPath = filepath.Join(dir, "leaf.pem")
	keyPath = filepath.Join(dir, "leaf.key")
	csr := filepath.Join(dir, "leaf.csr")
	run("req", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", csr,
		"-nodes", "-subj", "/CN=hysteria.test")

	ext := filepath.Join(dir, "leaf.ext")
	if err := os.WriteFile(ext, []byte("subjectAltName=DNS:hysteria.test,DNS:*.wild.test\n"), 0o600); err != nil {
		t.Fatalf("write ext: %v", err)
	}
	run("x509", "-req", "-in", csr, "-CA", caPath, "-CAkey", caKey,
		"-CAcreateserial", "-out", certPath, "-days", "2", "-extfile", ext)

	return caPath, certPath, keyPath
}

// leafPinHex returns the lowercase hex SHA-256 of the leaf certificate's DER
// -- the exact value hysteria's `tls.pinSHA256` takes (follow-up 2: hex,
// case-insensitive; base64 fails with "no certificate matches the pinned
// hash").
func leafPinHex(t *testing.T, certPath string) string {
	t.Helper()
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read leaf: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("no PEM block in %s", certPath)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	sum := sha256.Sum256(leaf.Raw)
	return hex.EncodeToString(sum[:])
}

// startCertModeServer brings up the real backend over the CA-signed leaf.
func startCertModeServer(t *testing.T, exe, certPath, keyPath string) int {
	t.Helper()
	apiPort := freePort(t)
	serverPort := freeUDPPort(t)
	h := newTestBackend(t, exe, serverConfigJSON("127.0.0.1:"+strconv.Itoa(serverPort), certPath, keyPath, nil), []*common.User{
		{
			Email:    "1",
			Proxies:  &common.Proxy{Hysteria: &common.Hysteria{Auth: "pw"}},
			Inbounds: []string{},
		},
	}, apiPort)
	if !h.Started() {
		t.Fatal("core reports not started")
	}
	return serverPort
}

// certModeClient brings up a real official client with the given tls block.
// waitForProxy=false for cases expected to fail (the proxy never binds).
func certModeClient(t *testing.T, exe, dir, name string, serverPort int, sni string, tlsExtra map[string]any, waitForProxy bool) (proxyPort int, logPath string) {
	t.Helper()
	tlsCfg := map[string]any{"sni": sni}
	for k, v := range tlsExtra {
		tlsCfg[k] = v
	}
	proxyPort = freePort(t)
	cfgPath := writeClientConfig(t, dir, name, clientConfigJSON(
		"127.0.0.1:"+strconv.Itoa(serverPort), "1:pw", proxyPort, map[string]any{"tls": tlsCfg}))
	return proxyPort, hysteriaClient(t, exe, cfgPath, proxyPort, waitForProxy)
}

// (a) default: the client verifies against the system roots and must fail.
// This is what the panel emits when the per-core TLS setting is untouched
// (no allowinsecure, no pin) -- the safe default.
func TestCertModeDefaultVerificationRefusesNonPublicCA(t *testing.T) {
	exe := requirePinnedBinary(t)
	dir := t.TempDir()
	_, certPath, keyPath := writeCAAndLeaf(t, dir)
	serverPort := startCertModeServer(t, exe, certPath, keyPath)
	targetPort := startHTTPOrigin(t, 4096)

	proxyPort, logPath := certModeClient(t, exe, dir, "client-default.json", serverPort,
		"hysteria.test", nil, false)
	if got := httpGetViaProxy(proxyPort, targetPort, 5*time.Second); got != 0 {
		t.Fatalf("default client moved %d bytes through a non-public CA; it must refuse", got)
	}
	t.Logf("default client refused, as required; log tail:\n%s", tailFile(t, logPath))
}

// (b) insecure=1: the same cert works. The operator's documented fix when
// they cannot pin (DEPLOY.md).
func TestCertModeInsecureWorks(t *testing.T) {
	exe := requirePinnedBinary(t)
	dir := t.TempDir()
	_, certPath, keyPath := writeCAAndLeaf(t, dir)
	serverPort := startCertModeServer(t, exe, certPath, keyPath)
	targetPort := startHTTPOrigin(t, 4096)

	proxyPort, logPath := certModeClient(t, exe, dir, "client-insecure.json", serverPort,
		"hysteria.test", map[string]any{"insecure": true}, true)
	if got := httpGetViaProxy(proxyPort, targetPort, 20*time.Second); got == 0 {
		t.Fatalf("insecure=1 client moved no bytes\n%s", tailFile(t, logPath))
	}
}

// (c) pinSHA256 (hex of the leaf) beside insecure: works, and the pin is a
// real check -- a wrong pin fails even with insecure=1.
func TestCertModeHexPinOfLeafWorks(t *testing.T) {
	exe := requirePinnedBinary(t)
	dir := t.TempDir()
	_, certPath, keyPath := writeCAAndLeaf(t, dir)
	pin := leafPinHex(t, certPath)
	serverPort := startCertModeServer(t, exe, certPath, keyPath)
	targetPort := startHTTPOrigin(t, 4096)

	proxyPort, logPath := certModeClient(t, exe, dir, "client-pin.json", serverPort,
		"hysteria.test", map[string]any{"insecure": true, "pinSHA256": pin}, true)
	if got := httpGetViaProxy(proxyPort, targetPort, 20*time.Second); got == 0 {
		t.Fatalf("pinning client (hex pin %s) moved no bytes\n%s", pin, tailFile(t, logPath))
	}
}

func TestCertModeWrongPinRefusesEvenWithInsecure(t *testing.T) {
	exe := requirePinnedBinary(t)
	dir := t.TempDir()
	_, certPath, keyPath := writeCAAndLeaf(t, dir)
	wrong := "0000000000000000000000000000000000000000000000000000000000000000"
	serverPort := startCertModeServer(t, exe, certPath, keyPath)
	targetPort := startHTTPOrigin(t, 4096)

	proxyPort, logPath := certModeClient(t, exe, dir, "client-wrongpin.json", serverPort,
		"hysteria.test", map[string]any{"insecure": true, "pinSHA256": wrong}, false)
	if got := httpGetViaProxy(proxyPort, targetPort, 5*time.Second); got != 0 {
		t.Fatalf("wrong pin moved %d bytes; the pin is not being checked", got)
	}
	t.Logf("wrong pin refused, as required; log tail:\n%s", tailFile(t, logPath))
}

// (d) sniGuard (default dns-san): an SNI outside the cert's DNS SANs is
// refused by the SERVER before the client's insecure can matter.
func TestCertModeSniGuardRefusesSNIOutsideSANs(t *testing.T) {
	exe := requirePinnedBinary(t)
	dir := t.TempDir()
	_, certPath, keyPath := writeCAAndLeaf(t, dir)
	serverPort := startCertModeServer(t, exe, certPath, keyPath)
	targetPort := startHTTPOrigin(t, 4096)

	proxyPort, logPath := certModeClient(t, exe, dir, "client-foreignsni.json", serverPort,
		"not-in-sans.example", map[string]any{"insecure": true}, false)
	if got := httpGetViaProxy(proxyPort, targetPort, 5*time.Second); got != 0 {
		t.Fatalf("server accepted SNI not-in-sans.example; sniGuard is not guarding")
	}
	t.Logf("sniGuard refused the foreign SNI, as required; log tail:\n%s", tailFile(t, logPath))
}

// (d) the same guard accepts an SNI that the wildcard SAN covers -- the
// Cloudflare-Origin wildcard case.
func TestCertModeSniGuardAcceptsSNIInsideWildcardSAN(t *testing.T) {
	exe := requirePinnedBinary(t)
	dir := t.TempDir()
	_, certPath, keyPath := writeCAAndLeaf(t, dir)
	serverPort := startCertModeServer(t, exe, certPath, keyPath)
	targetPort := startHTTPOrigin(t, 4096)

	proxyPort, logPath := certModeClient(t, exe, dir, "client-wildsni.json", serverPort,
		"foo.wild.test", map[string]any{"insecure": true}, true)
	if got := httpGetViaProxy(proxyPort, targetPort, 20*time.Second); got == 0 {
		t.Fatalf("wildcard SAN foo.wild.test did not satisfy sniGuard\n%s", tailFile(t, logPath))
	}
}
