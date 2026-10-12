package openvpn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The node owns the whole PKI for one core: no operator-supplied CA, no
// openssl(1) subprocess, no network. crypto/x509 is the standard library and
// OpenVPN only needs PEM files it can hand to OpenSSL itself.
const (
	caCommonName     = "PasarGuard OpenVPN CA"
	serverCommonName = "pasarguard-openvpn-server"
	caValidity       = 20 * 365 * 24 * time.Hour
	serverValidity   = 10 * 365 * 24 * time.Hour
)

const (
	caCertFile   = "ca.crt"
	caKeyFile    = "ca.key"
	serverCert   = "server.crt"
	serverKey    = "server.key"
	tlsCryptFile = "tls-crypt.key"
)

// ensurePKI materialises the files server.conf points at and forces 0600 on
// every one that exists.
//
// Two sources, in this order:
//
//   - The panel's core config, when the operator pasted a certificate set in.
//     Those bytes are authoritative and are written on every start: a
//     panel-side change has to reach the node, and there is no RPC to read
//     node-generated PKI back (CONTRACT 6.4), so a generated file could never
//     be shown to anyone and must not win over a paste.
//   - Node-generated, only when a file is absent. A restart must never hand a
//     client a CA the server no longer trusts.
//
// A partial set is refused in Config.validatePKI, so this never guesses.
func ensurePKI(dir string, cfg *Config) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("openvpn: creating config directory: %w", err)
	}
	if cfg == nil {
		cfg = &Config{}
	}

	if cfg.SuppliedPKI() {
		for _, f := range []struct{ name, body string }{
			{caCertFile, cfg.CA},
			{serverCert, cfg.Cert},
			{serverKey, cfg.Key},
		} {
			if err := writePEM(filepath.Join(dir, f.name), f.body); err != nil {
				return fmt.Errorf("openvpn: writing supplied %s: %w", f.name, err)
			}
		}
		if err := checkSuppliedPKI(dir); err != nil {
			return err
		}
	} else {
		if !bothExist(dir, caCertFile, caKeyFile) {
			if err := writeCA(dir); err != nil {
				return err
			}
		}
		if !bothExist(dir, serverCert, serverKey) {
			if err := writeServerCert(dir); err != nil {
				return err
			}
		}
	}

	switch {
	case cfg.TLSCrypt != "":
		if err := writePEM(filepath.Join(dir, tlsCryptFile), cfg.TLSCrypt); err != nil {
			return fmt.Errorf("openvpn: writing supplied tls_crypt: %w", err)
		}
	case !exists(filepath.Join(dir, tlsCryptFile)):
		key, err := staticKey()
		if err != nil {
			return err
		}
		if err := writeSecret(filepath.Join(dir, tlsCryptFile), key); err != nil {
			return err
		}
	}

	for _, name := range []string{caCertFile, caKeyFile, serverCert, serverKey, tlsCryptFile} {
		path := filepath.Join(dir, name)
		if !exists(path) {
			continue // an operator-pasted set carries no ca.key; nothing to tighten
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("openvpn: tightening %s to 0600: %w", name, err)
		}
	}
	return nil
}

// writePEM writes a pasted PEM/key body verbatim (normalised to one trailing
// newline) at 0600.
func writePEM(path, body string) error {
	return os.WriteFile(path, []byte(strings.TrimRight(body, "\r\n")+"\n"), 0o600)
}

// checkSuppliedPKI parses what the operator pasted and proves the three pieces
// belong together. A mismatch here is a core that starts and then fails every
// handshake with a TLS error the panel cannot explain — refused at start
// instead, naming the file.
func checkSuppliedPKI(dir string) error {
	ca, err := readCACert(dir)
	if err != nil {
		return err
	}
	leafPEM, err := os.ReadFile(filepath.Join(dir, serverCert))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		return fmt.Errorf("openvpn: %s is not PEM", serverCert)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("openvpn: parsing %s: %w", serverCert, err)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("openvpn: the supplied %s is not signed by the supplied %s: %w", serverCert, caCertFile, err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, serverKey))
	if err != nil {
		return err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("openvpn: %s is not PEM", serverKey)
	}
	parsed, err := parseAnyKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("openvpn: parsing %s: %w", serverKey, err)
	}
	pub, err := publicKeyOf(parsed)
	if err != nil {
		return err
	}
	if !publicKeysEqual(pub, leaf.PublicKey) {
		return fmt.Errorf("openvpn: the supplied %s does not match the public key in %s", serverKey, serverCert)
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func bothExist(dir string, a, b string) bool {
	return exists(filepath.Join(dir, a)) && exists(filepath.Join(dir, b))
}

// writeSecret writes a PEM/private file 0600. Truncating rather than
// appending: a half-written key from a killed run must not be reused.
func writeSecret(path string, blocks []byte) error {
	return os.WriteFile(path, blocks, 0o600)
}

func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func randomSerial() (*big.Int, error) {
	// 128 random bits: unique per certificate, no counter to keep across a
	// restart or to collide between two cores on one node.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func writeCA(dir string) error {
	key, err := newKey()
	if err != nil {
		return fmt.Errorf("openvpn: generating CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return fmt.Errorf("openvpn: generating CA serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caCommonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("openvpn: signing CA certificate: %w", err)
	}
	if err := writeSecret(filepath.Join(dir, caCertFile), pemBlock("CERTIFICATE", der)); err != nil {
		return err
	}
	return writeKey(filepath.Join(dir, caKeyFile), key)
}

func writeServerCert(dir string) error {
	caCert, caKey, err := readCA(dir)
	if err != nil {
		return err
	}
	key, err := newKey()
	if err != nil {
		return fmt.Errorf("openvpn: generating server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return fmt.Errorf("openvpn: generating server serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverCommonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(serverValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("openvpn: signing server certificate: %w", err)
	}
	if err := writeSecret(filepath.Join(dir, serverCert), pemBlock("CERTIFICATE", der)); err != nil {
		return err
	}
	return writeKey(filepath.Join(dir, serverKey), key)
}

func readCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, nil, fmt.Errorf("openvpn: reading CA certificate: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("openvpn: %s is not PEM", caCertFile)
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("openvpn: parsing %s: %w", caCertFile, err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("openvpn: reading CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("openvpn: %s is not PEM", caKeyFile)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("openvpn: parsing %s: %w", caKeyFile, err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("openvpn: %s is not an EC key", caKeyFile)
	}
	return caCert, ec, nil
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("openvpn: marshalling key: %w", err)
	}
	return writeSecret(path, pemBlock("PRIVATE KEY", der))
}

// staticKey renders an OpenVPN static key: 256 random bytes written as the
// exact layout `openvpn --genkey secret` produces — 16 rows of 32 lowercase hex
// digits between the V1 markers (verified against upstream's own
// sample/sample-keys/ta.key, header "# 2048 bit OpenVPN static key").
//
// Generated here rather than by shelling out to `--genkey` so config render has
// no dependency on the binary being present at that moment, and so the format
// is asserted by a test instead of inherited from whatever version is installed.
func staticKey() ([]byte, error) {
	raw := make([]byte, 256)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("openvpn: generating tls-crypt key: %w", err)
	}
	out := []byte("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n")
	hexed := hex.EncodeToString(raw)
	for i := 0; i < len(hexed); i += 32 {
		out = append(out, hexed[i:i+32]...)
		out = append(out, '\n')
	}
	out = append(out, []byte("-----END OpenVPN Static key V1-----\n")...)
	return out, nil
}

// readCACert parses only the CA certificate — an operator-pasted set carries no
// ca.key, so readCA (which needs the key to sign) does not apply.
func readCACert(dir string) (*x509.Certificate, error) {
	body, err := os.ReadFile(filepath.Join(dir, caCertFile))
	if err != nil {
		return nil, fmt.Errorf("openvpn: reading %s: %w", caCertFile, err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("openvpn: %s is not PEM", caCertFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("openvpn: parsing %s: %w", caCertFile, err)
	}
	return cert, nil
}

// parseAnyKey accepts the three private-key encodings a paste can reasonably
// carry: PKCS#8 (what this package writes), PKCS#1 RSA, and SEC1 EC.
func parseAnyKey(der []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("not a PKCS#8, PKCS#1 or SEC1 private key")
}

func publicKeyOf(key any) (crypto.PublicKey, error) {
	type publicer interface{ Public() crypto.PublicKey }
	if k, ok := key.(publicer); ok {
		return k.Public(), nil
	}
	return nil, fmt.Errorf("unsupported private key type %T", key)
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}
