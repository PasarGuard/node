package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeTestPair(t *testing.T, certFile, keyFile string, serial int64, from, to time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: from, NotAfter: to, DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestReloadValidationAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	now := time.Now()
	writeTestPair(t, certFile, keyFile, 1, now.Add(-time.Hour), now.Add(time.Hour))
	h, err := NewCertificateHolder(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	original := h.active.Load()
	key, _ := os.ReadFile(keyFile)
	for _, test := range []struct {
		name     string
		from, to time.Time
	}{
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour)},
		{"future", now.Add(time.Hour), now.Add(2 * time.Hour)},
		{"mismatched", now.Add(-time.Hour), now.Add(time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			writeTestPair(t, certFile, keyFile, 2, test.from, test.to)
			if test.name == "mismatched" {
				if err := os.WriteFile(keyFile, key, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.Reload(); err == nil {
				t.Fatal("invalid replacement accepted")
			}
			if h.active.Load() != original {
				t.Fatal("active certificate changed on failure")
			}
			if _, err := NewCertificateHolder(certFile, keyFile); err == nil {
				t.Fatal("invalid startup accepted")
			}
		})
	}
	if err := os.WriteFile(certFile, []byte("invalid PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.Reload(); err == nil || h.active.Load() != original {
		t.Fatal("malformed PEM not retained")
	}
	writeTestPair(t, certFile, keyFile, 3, now.Add(-time.Hour), now.Add(time.Hour))
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if err := h.Reload(); err != nil {
				t.Error(err)
			}
			_, _ = h.TLSConfig().GetCertificate(nil)
			_ = h.Status()
		})
	}
	wg.Wait()
	if h.active.Load().Leaf.SerialNumber.Int64() != 3 {
		t.Fatal("replacement not active")
	}
	var disabled *CertificateHolder
	disabled.LogReload(func(string, ...any) {})
}

func TestTLSConnectionsSurviveReloadAndExpiry(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	now := time.Now()
	// Expiry is advanced via the client clock, without a wall-clock sleep.
	writeTestPair(t, certFile, keyFile, 1, now.Add(-time.Hour), now.Add(time.Hour))
	h, err := NewCertificateHolder(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(h.active.Load().Leaf)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", h.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	clientConfig := &tls.Config{RootCAs: pool, ServerName: "localhost"}
	dial := func(cfg *tls.Config) (*tls.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), cfg)
	}
	established, err := dial(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer established.Close()
	check := func() {
		t.Helper()
		_ = established.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := established.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 2)
		if _, err := io.ReadFull(established, b); err != nil {
			t.Fatal(err)
		}
		if string(b) != "ok" {
			t.Fatal(string(b))
		}
	}
	check()
	expiredConfig := clientConfig.Clone()
	expiredConfig.Time = func() time.Time { return now.Add(2 * time.Hour) }
	if c, err := dial(expiredConfig); err == nil {
		c.Close()
		t.Fatal("fresh handshake accepted expired certificate")
	}
	check()
	writeTestPair(t, certFile, keyFile, 2, now.Add(-time.Hour), now.Add(4*time.Hour))
	if err := h.Reload(); err != nil {
		t.Fatal(err)
	}
	pool.AddCert(h.active.Load().Leaf)
	fresh, err := dial(expiredConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != 2 {
		t.Fatal("fresh handshake received old certificate")
	}
	check()
}
