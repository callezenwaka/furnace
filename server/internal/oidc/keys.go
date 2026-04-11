package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"

	jose "github.com/go-jose/go-jose/v3"
)

// KeyManager holds the active RSA signing key and its published JWK set.
// A single 2048-bit key is generated at construction and rotated only on demand.
type KeyManager struct {
	mu         sync.RWMutex
	privateKey *rsa.PrivateKey
	keyID      string
	jwks       jose.JSONWebKeySet
}

func NewKeyManager() (*KeyManager, error) {
	km := &KeyManager{}
	if err := km.rotate(); err != nil {
		return nil, err
	}
	return km, nil
}

// rotate generates a new RSA key pair and updates the published JWKS.
func (km *KeyManager) rotate() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate rsa key: %w", err)
	}

	kid, err := randomID(8)
	if err != nil {
		return fmt.Errorf("generate key id: %w", err)
	}

	pub := jose.JSONWebKey{
		Key:       &priv.PublicKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}

	km.mu.Lock()
	defer km.mu.Unlock()
	km.privateKey = priv
	km.keyID = kid
	km.jwks = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}}
	return nil
}

// Signer returns a JWS signer for the active key.
func (km *KeyManager) Signer() (jose.Signer, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: km.privateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", km.keyID),
	)
	if err != nil {
		return nil, fmt.Errorf("new signer: %w", err)
	}
	return sig, nil
}

// JWKS returns the public key set for the /.well-known/jwks.json endpoint.
func (km *KeyManager) JWKS() jose.JSONWebKeySet {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.jwks
}
