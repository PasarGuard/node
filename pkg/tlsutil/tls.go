package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pasarguard/node/config"
)

// ValidateListener also guards direct callers that bypass config.Load.
func ValidateListener(tlsConfig *tls.Config, addr string, cfg *config.Config) error {
	if tlsConfig != nil {
		return nil
	}
	if cfg.TLSEnabled {
		return fmt.Errorf("TLS_ENABLED=true requires TLS credentials")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	_, err = config.PrivateBackendHost(host)
	return err
}

func LoadTLSCredentials(cert, key string) (*tls.Config, error) {
	holder, err := NewCertificateHolder(cert, key)
	if err != nil {
		return nil, err
	}
	return holder.TLSConfig(), nil
}

func LoadClientPool(cert string) (*x509.CertPool, error) {
	pemServerCA, err := os.ReadFile(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to read server certificate: %v", err)
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

	return certPool, nil
}

func CreateHTTPClient(certPool *x509.CertPool, hostname string) *http.Client {
	tlsConfig := &tls.Config{RootCAs: certPool, ServerName: hostname}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Protocols:       new(http.Protocols),
	}
	transport.Protocols.SetHTTP2(true)

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
}
