package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
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

// ensurePKI creates whatever of the five files is missing and forces 0600 on
// all of them. Files are never rewritten while they exist: a restart must not
// hand a client a CA the server no longer trusts.
func ensurePKI(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("openvpn: creating config directory: %w", err)
	}

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
	if !exists(filepath.Join(dir, tlsCryptFile)) {
		key, err := staticKey()
		if err != nil {
			return err
		}
		if err := writeSecret(filepath.Join(dir, tlsCryptFile), key); err != nil {
			return err
		}
	}
	for _, name := range []string{caCertFile, caKeyFile, serverCert, serverKey, tlsCryptFile} {
		if err := os.Chmod(filepath.Join(dir, name), 0o600); err != nil {
			return fmt.Errorf("openvpn: tightening %s to 0600: %w", name, err)
		}
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
