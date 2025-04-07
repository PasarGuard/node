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
	}
	if isClient {
		config.RootCAs = certPool
	} else {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = certPool
	}
	return config, nil
}
