package authserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// PKCE lengths from RFC 7636 section 4.1: a verifier is 43 to 128 characters,
// and an S256 challenge is the 43-character base64url digest of one.
const (
	minVerifierLength = 43
	maxVerifierLength = 128
	challengeLength   = 43
)

// validCodeChallenge reports whether challenge is shaped like an S256
// challenge. The shape is all that can be checked until the verifier arrives.
func validCodeChallenge(challenge string) bool {
	return len(challenge) == challengeLength && isUnreserved(challenge)
}

// verifyPKCE reports whether verifier is the preimage of challenge under S256.
func verifyPKCE(challenge, verifier string) bool {
	if len(verifier) < minVerifierLength || len(verifier) > maxVerifierLength || !isUnreserved(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	derived := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(derived), []byte(challenge)) == 1
}

// isUnreserved reports whether s is made only of RFC 3986 unreserved
// characters, the alphabet PKCE values are drawn from.
func isUnreserved(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}
