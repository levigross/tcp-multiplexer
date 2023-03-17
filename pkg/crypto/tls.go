package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math"
	"math/big"
	"os"
	"time"

	"github.com/levigross/logger/logger"
	"go.uber.org/zap"
)

var log = logger.WithName("crypto")

func GenerateTLSConfigFromFile(key, cert string) (*tls.Config, error) {
	keyFile, err := os.ReadFile(key)
	if err != nil {
		log.Error("Unable to read key file", zap.Error(err))
		return nil, err
	}
	certFile, err := os.ReadFile(cert)
	if err != nil {
		log.Error("Unable to read cert file", zap.Error(err))
		return nil, err
	}
	certKeyPair, err := tls.X509KeyPair(certFile, keyFile)
	if err != nil {
		log.Error("Failed to load X509 key pair", zap.Error(err))
	}

	// Create a tls.Config using the certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certKeyPair},
		MinVersion:   tls.VersionTLS13, // Set TLS 1.3 as the minimum version
		NextProtos:   []string{"quic"},
	}
	return tlsConfig, err
}

func GenerateTLSConfigInMemory() (*tls.Config, error) {
	log.Debug("Generating ed25519 key")
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Error("unable to generate ed25519", zap.Error(err))
		return nil, err

	}

	hostName, err := os.Hostname()
	if err != nil {
		log.Error("Unable to get hostname", zap.Error(err))
		return nil, err
	}

	log.Debug("Generating x509 certificate")

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64))
	if err != nil {
		log.Error("Unable to generate x509 serial number")
		return nil, err
	}

	// todo add SAN from JWT

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{hostName},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, privKey)
	if err != nil {
		log.Error("Unable to generate x509 certificate", zap.Error(err))
		return nil, err
	}

	derKey, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		log.Error("Unable to marshal private key into PKCS8", zap.Error(err))
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derKey})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Error("Unable to generate x509 key pair", zap.Error(err))
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"quic"},
	}

	log.Debug("tls.config generated")

	return tlsConfig, nil
}
