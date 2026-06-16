package service

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

type MTLSService struct {
	certStore map[string]*x509.Certificate // thumbprint -> certificate
	mu        sync.RWMutex
	crl       *x509.RevocationList
	crlPath   string
	crlLoaded bool
}

func NewMTLSService() *MTLSService {
	return &MTLSService{
		certStore: make(map[string]*x509.Certificate),
	}
}

// SetCRLPath sets the CRL file path and loads it
func (s *MTLSService) SetCRLPath(crlPath string) error {
	s.crlPath = crlPath
	return s.LoadCRL()
}

// LoadCRL loads the CRL from the configured path
func (s *MTLSService) LoadCRL() error {
	if s.crlPath == "" {
		return nil
	}

	data, err := os.ReadFile(s.crlPath)
	if err != nil {
		return fmt.Errorf("failed to read CRL file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from CRL")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	s.crl = crl
	s.crlLoaded = true
	return nil
}

// ExtractClientCertificate extracts the client certificate from the TLS connection
func (s *MTLSService) ExtractClientCertificate(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

// ValidateClientCertificate validates the client certificate
func (s *MTLSService) ValidateClientCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	if cert == nil {
		return fmt.Errorf("no client certificate provided")
	}

	// Check CRL first
	if s.crlLoaded {
		if s.IsCertificateRevoked(cert) {
			return fmt.Errorf("certificate has been revoked")
		}
	}

	// Create verification options
	opts := x509.VerifyOptions{
		Roots: roots,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	// Verify the certificate
	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	// Check expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}

	return nil
}

// IsCertificateRevoked checks if a certificate is in the CRL
func (s *MTLSService) IsCertificateRevoked(cert *x509.Certificate) bool {
	if !s.crlLoaded || s.crl == nil {
		return false
	}

	for _, revoked := range s.crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}

	return false
}

// GetCertificateThumbprint returns the SHA-256 thumbprint of a certificate
func (s *MTLSService) GetCertificateThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// StoreCertificate stores a certificate for later lookup
func (s *MTLSService) StoreCertificate(thumbprint string, cert *x509.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certStore[thumbprint] = cert
}

// GetCertificate retrieves a certificate by thumbprint
func (s *MTLSService) GetCertificate(thumbprint string) *x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certStore[thumbprint]
}

// ValidateClientAuthType validates the client authentication type
func (s *MTLSService) ValidateClientAuthType(cert *x509.Certificate, expectedType string) error {
	if cert == nil {
		return fmt.Errorf("no certificate provided")
	}

	// Check if the certificate has the expected key usage
	switch expectedType {
	case "tls_client_auth":
		// Standard TLS client auth
		return nil
	case "self_signed_tls_client_auth":
		// Self-signed certificate auth
		return nil
	default:
		return fmt.Errorf("unsupported client auth type: %s", expectedType)
	}
}

// CreateCertificateBoundToken creates a certificate-bound access token
func (s *MTLSService) CreateCertificateBoundToken(token string, cert *x509.Certificate) string {
	// In production, this would store the binding
	thumbprint := s.GetCertificateThumbprint(cert)
	return fmt.Sprintf("%s?cert_thumbprint=%s", token, thumbprint)
}

// ValidateCertificateBinding validates that a token is bound to a certificate
func (s *MTLSService) ValidateCertificateBinding(token string, cert *x509.Certificate) error {
	// In production, this would check the binding in the database
	if cert == nil {
		return fmt.Errorf("no certificate provided")
	}
	return nil
}

// ParseClientCertHeader parses the client certificate from a header (for reverse proxy setups)
func (s *MTLSService) ParseClientCertHeader(header string) (*x509.Certificate, error) {
	if header == "" {
		return nil, fmt.Errorf("no certificate header provided")
	}

	// Decode the PEM-encoded certificate
	certDER, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// CreateTLSConfig creates a TLS configuration for mTLS
func (s *MTLSService) CreateTLSConfig(certPool *x509.CertPool) *tls.Config {
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  certPool,
	}
}
