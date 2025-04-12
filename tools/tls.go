package tools

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
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

	// Create a certificate pool and add the server's certificate
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, errors.New("failed to add server CA's certificate")
	}
	return certPool, nil
}
