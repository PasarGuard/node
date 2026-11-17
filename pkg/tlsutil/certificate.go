package tlsutil

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// CertificateHolder keeps handshakes independent of file access and reloads.
// Certificates published here are immutable; existing connections retain theirs.
type CertificateHolder struct {
	certFile, keyFile string
	mu                sync.Mutex
	active            atomic.Pointer[tls.Certificate]
}

func NewCertificateHolder(certFile, keyFile string) (*CertificateHolder, error) {
	h := &CertificateHolder{certFile: certFile, keyFile: keyFile}
	if err := h.Reload(); err != nil {
		return nil, err
	}
	return h, nil
}

// Reload serializes file reads and publishes only a complete, currently valid pair.
func (h *CertificateHolder) Reload() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	cert, err := tls.LoadX509KeyPair(h.certFile, h.keyFile)
	if err != nil {
		return err
	}
	now := time.Now()
	for i, der := range cert.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		if now.Before(parsed.NotBefore) || !now.Before(parsed.NotAfter) {
			return fmt.Errorf("certificate %d is outside its validity period (%s to %s)", i, parsed.NotBefore.Format(time.RFC3339), parsed.NotAfter.Format(time.RFC3339))
		}
		if i == 0 {
			cert.Leaf = parsed
		}
	}
	h.active.Store(&cert)
	return nil
}

func (h *CertificateHolder) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return h.active.Load(), nil },
	}
}

// Status describes the active in-memory leaf, even if files have been replaced.
func (h *CertificateHolder) Status() string {
	cert := h.active.Load()
	return fmt.Sprintf("fingerprint=sha256:%x expiry=%s", sha256.Sum256(cert.Certificate[0]), cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
}

// LogReload also handles external TLS mode, where no holder exists.
func (h *CertificateHolder) LogReload(logf func(string, ...any)) {
	if h == nil {
		logf("TLS reload: no-op (TLS disabled for external termination)")
		return
	}
	if err := h.Reload(); err != nil {
		logf("TLS reload failed: %v; retained active %s", err, h.Status())
		return
	}
	logf("TLS reload succeeded: active %s", h.Status())
}
