package tools

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func LoadTLSCredentials(cert, key, poolCert string, isClient bool) (*tls.Config, error) {
	pem, err := os.ReadFile(poolCert)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("failed to add CA's certificate")
	}

	serverCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}
	if isClient {
		config.InsecureSkipVerify = true
	}
	return config, nil
}

func LoadCertPool(certFile string) *x509.CertPool {
	certPool := x509.NewCertPool()
	certData, err := os.ReadFile(certFile)
	if err == nil {
		certPool.AppendCertsFromPEM(certData)
	}
	return certPool
}
