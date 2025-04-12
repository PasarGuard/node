package tools

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

func LoadTLSCredentials(cert, key string) (*tls.Config, error) {
	serverCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}
	return config, nil
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
