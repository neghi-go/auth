package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

type encoding string

var (
	hex_encoding    encoding = "hex"
	base64_encoding encoding = "base64"
)

type method string

var (
	s256  method = "S256"
	plain method = "plain"
)

func generateVerifier(length int) string {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func generateChallenge(verifier string, encoding encoding, method method) string {
	if method == plain {
		return verifier
	}
	sha := sha256.Sum256([]byte(verifier))
	switch encoding {
	case hex_encoding:
		return hex.EncodeToString(sha[:])
	case base64_encoding:
		return base64.RawURLEncoding.EncodeToString(sha[:])
	default:
		return ""
	}
}
