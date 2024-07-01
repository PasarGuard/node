package tools

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"marzban-node/config"
	log "marzban-node/logger"
	"math/big"
	"os"
	"time"
)

func generateCertificate() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(100 * 365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Gozargah",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", err
	}

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return string(certOut), string(keyOut), nil
}

func RewriteSslFile() {
	cert, key, err := generateCertificate()
	if err != nil {
		panic(err)
	}

	// Write certificate to file
	certFile, err := os.Create(config.SslCertFile)
	if err != nil {
		log.Error("Problem in creating SslCert File: ", err)
		return
	}
	defer certFile.Close()

	_, err = certFile.WriteString(cert)
	if err != nil {
		log.Error("Problem in writing SslCert File: ", err)
		return
	}

	// Write key to file
	keyFile, err := os.Create(config.SslKeyFile)
	if err != nil {
		log.Error("Problem in creating SslKey File: ", err)
		return
	}
	defer keyFile.Close()

	_, err = keyFile.WriteString(key)
	if err != nil {
		log.Error("Problem in writing SslKey File: ", err)
		return
	}
}
