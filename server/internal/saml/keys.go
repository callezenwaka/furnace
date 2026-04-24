package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	certFileName = "saml-idp.crt"
	keyFileName  = "saml-idp.key"
)

// CertManager holds the RSA key and self-signed certificate used for SAML signing.
type CertManager struct {
	mu   sync.RWMutex
	key  *rsa.PrivateKey
	cert *x509.Certificate
	der  []byte // DER-encoded cert for inclusion in metadata/signatures
}

// NewCertManager generates a fresh ephemeral RSA-2048 key and self-signed certificate.
func NewCertManager() (*CertManager, error) {
	return generate()
}

// NewCertManagerFromPath loads an existing key+cert from dir, or generates and
// persists new ones if the files don't exist yet. dir may be empty (""), in which
// case it falls back to NewCertManager (ephemeral).
func NewCertManagerFromPath(dir string) (*CertManager, error) {
	if dir == "" {
		return NewCertManager()
	}

	keyPath := filepath.Join(dir, keyFileName)
	certPath := filepath.Join(dir, certFileName)

	// Try to load existing files.
	if cm, err := load(keyPath, certPath); err == nil {
		return cm, nil
	}

	// Generate fresh key+cert.
	cm, err := generate()
	if err != nil {
		return nil, err
	}

	// Persist to disk. Best-effort — if the dir isn't writable we still return
	// the in-memory manager rather than failing startup.
	if err := os.MkdirAll(dir, 0o700); err == nil {
		_ = saveKey(keyPath, cm.key)
		_ = saveCert(certPath, cm.der)
	}

	return cm, nil
}

func generate() (*CertManager, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("saml: generate rsa key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("saml: generate serial: %w", err)
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Furnace SAML IdP",
			Organization: []string{"Furnace"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("saml: create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("saml: parse certificate: %w", err)
	}

	return &CertManager{key: key, cert: cert, der: der}, nil
}

func load(keyPath, certPath string) (*CertManager, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("saml: no PEM block in key file")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS1 as fallback.
		rsaKey, err2 := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("saml: parse private key: %w", err)
		}
		key = rsaKey
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("saml: key file does not contain an RSA key")
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("saml: no PEM block in cert file")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("saml: parse certificate: %w", err)
	}

	return &CertManager{key: rsaKey, cert: cert, der: certBlock.Bytes}, nil
}

func saveKey(path string, key *rsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return os.WriteFile(path, block, 0o600)
}

func saveCert(path string, der []byte) error {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return os.WriteFile(path, block, 0o644)
}

// PrivateKey returns the RSA signing key.
func (cm *CertManager) PrivateKey() *rsa.PrivateKey {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.key
}

// Certificate returns the parsed x509 certificate.
func (cm *CertManager) Certificate() *x509.Certificate {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.cert
}

// CertDER returns the raw DER bytes of the certificate.
func (cm *CertManager) CertDER() []byte {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	cp := make([]byte, len(cm.der))
	copy(cp, cm.der)
	return cp
}

// CertPEM returns the PEM-encoded certificate (for display/download).
func (cm *CertManager) CertPEM() []byte {
	der := cm.CertDER()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
