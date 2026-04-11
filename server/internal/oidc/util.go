package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// randomID returns a hex-encoded random string of byteLen bytes.
func randomID(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
