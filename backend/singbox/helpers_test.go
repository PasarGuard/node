package singbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// freePort returns a port that was free at call time. The listener is closed
// before returning, so callers must bind it promptly; the tests run serially
// (-p 1) to keep that window free of races.
func freePort(t *testing.T) int {
	t.Helper()
	return freePorts(t, 1)[0]
}

// reservedPorts remembers every port handed out this process and every
// apiPort+1 neighbour the core may bind, so separate freePort() calls cannot
// straddle it. Tests run serially (-p 1), so one set for the package is enough.
var (
	reservedMu sync.Mutex
	reserved   = map[int]bool{}
)

// freePorts returns n pairwise-distinct ports that were all free
// simultaneously. Holding every listener until the set is complete prevents
// the allocator from handing the same port to two call sites (which would
// make a later waitForPort "succeed" against the wrong service).
//
// Adjacent ports are also rejected. The quota control endpoint is apiPort+1
// (Core.QuotaEndpointPort) and the node binds it from the very first start, so
// a neighbouring allocation is not merely unlucky: the core claims a port the
// test believes it owns. The symptom points nowhere near the cause — the core
// answers on what should be the client's SOCKS port and the test fails with
// "unexpected socks version byte 0x48" ('H', from an HTTP reply).
//
// Windows hands out consecutive ephemeral ports from one counter, so with
// ports taken one freePort() call at a time this collided essentially always.
func freePorts(t *testing.T, n int) []int {
	t.Helper()
	listeners := make([]net.Listener, 0, n)
	for len(listeners) < n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("freePorts: %v", err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		reservedMu.Lock()
		// Reject port and both neighbours: port-1's quota port is this port,
		// this port's quota port is port+1, and port itself must be unused.
		unsafe := reserved[port] || reserved[port-1] || reserved[port+1]
		if !unsafe {
			reserved[port] = true
			if port < 65535 {
				reserved[port+1] = true // the quota endpoint this port may spawn
			}
		}
		reservedMu.Unlock()
		if unsafe {
			_ = l.Close()
			continue
		}
		listeners = append(listeners, l)
	}
	ports := make([]int, n)
	for i, l := range listeners {
		ports[i] = l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
	}
	return ports
}

// sprintfConfig is fmt.Sprintf with a clearer name at call sites.
func sprintfConfig(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

var certOnce struct {
	cert string
	key  string
	err  error
}

// testCert generates a self-signed cert once per test binary run and returns
// its file paths as slash-separated (JSON-safe) paths.
func testCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := filepath.Join(os.TempDir(), "singbox-test-certs")
	if certOnce.cert == "" && certOnce.err == nil {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir certs: %v", err)
		}
		certOnce.cert, certOnce.key, certOnce.err = generateSelfSigned(dir)
	}
	if certOnce.err != nil {
		t.Fatalf("generate cert: %v", certOnce.err)
	}
	return filepath.ToSlash(certOnce.cert), filepath.ToSlash(certOnce.key)
}

func generateSelfSigned(dir string) (certPath, keyPath string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath)
	if err != nil {
		return "", "", err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		certOut.Close()
		return "", "", err
	}
	certOut.Close()

	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return "", "", err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}); err != nil {
		keyOut.Close()
		return "", "", err
	}
	keyOut.Close()

	return certPath, keyPath, nil
}

// startOrigin is a local TCP origin standing in for the internet: it writes
// 2 KiB then drains until the peer closes (an early close would RST the
// client's in-flight upload and discard the receive buffer).
func startOrigin(t *testing.T, port int) net.Listener {
	t.Helper()
	origin, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	t.Cleanup(func() { _ = origin.Close() })
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write(make([]byte, 2048))
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return origin
}
