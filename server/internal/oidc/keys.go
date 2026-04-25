package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
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

// VerifyJWT parses and verifies a compact JWS token signed by the active key.
// Returns the decoded claims map and whether the token is currently active
// (signature valid and not expired). A parse error returns (nil, false, nil);
// a crypto error returns (nil, false, err).
func (km *KeyManager) VerifyJWT(token string) (claims map[string]any, active bool, err error) {
	km.mu.RLock()
	pubKey := km.jwks
	km.mu.RUnlock()

	// Build a verifier from the published public keys.
	jws, parseErr := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if parseErr != nil {
		return nil, false, nil // unparseable → inactive, not an error
	}

	// Try each key in the set.
	var payload []byte
	for _, k := range pubKey.Keys {
		if p, verifyErr := jws.Verify(k); verifyErr == nil {
			payload = p
			break
		}
	}
	if payload == nil {
		return nil, false, nil // signature invalid → inactive
	}

	var c map[string]any
	if jsonErr := json.Unmarshal(payload, &c); jsonErr != nil {
		return nil, false, fmt.Errorf("unmarshal claims: %w", jsonErr)
	}

	// Check expiry.
	active = true
	if expRaw, ok := c["exp"]; ok {
		var expUnix float64
		switch v := expRaw.(type) {
		case float64:
			expUnix = v
		case json.Number:
			expUnix, _ = v.Float64()
		}
		if expUnix > 0 && time.Now().UTC().After(time.Unix(int64(expUnix), 0)) {
			active = false
		}
	}

	// Normalise scope: space-delimited string or array → string.
	if sc, ok := c["scope"]; ok {
		switch v := sc.(type) {
		case []any:
			parts := make([]string, 0, len(v))
			for _, s := range v {
				parts = append(parts, fmt.Sprint(s))
			}
			c["scope"] = strings.Join(parts, " ")
		}
	}

	return c, active, nil
}
