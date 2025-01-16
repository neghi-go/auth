package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Algo string

const (
	RS256 Algo = "RS256"
)

var (
	ErrPrivateKeyEmpty = errors.New("empty private key")
	ErrPublicKeyEmpty  = errors.New("empty public key")
)

func (a Algo) String() string {
	return string(a)
}

type Options func(*JWT)

type JWT struct {
	algo        Algo
	private_key *rsa.PrivateKey
	public_key  any
}

func New(opts ...Options) (*JWT, error) {
	cfg := &JWT{
		algo: RS256,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.private_key == nil {
		return nil, ErrPrivateKeyEmpty
	}
	if cfg.public_key == nil {
		return nil, ErrPublicKeyEmpty
	}

	return cfg, nil
}

// WithPrivateKey expects a base64 encoded string of the
// private key
func WithPrivateKey(private_key string) Options {
	pri, _ := base64.StdEncoding.DecodeString(private_key)
	block, _ := pem.Decode(pri)
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return func(j *JWT) {
		j.private_key = privateKey
	}
}

// WithPublicKey expects a base64 encoded string of the
// public key
func WithPublicKey(public_key string) Options {
	pub, _ := base64.StdEncoding.DecodeString(public_key)
	block, _ := pem.Decode(pub)
	publicKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
	return func(j *JWT) {
		j.public_key = publicKey
	}
}

type ClaimsOptions func(*Claims)

type Claims struct {
	issuer   string
	audience string
	subject  string
	issuedAt time.Time
	exp      time.Time
	data     map[string]interface{}
}

func JWTClaims(opts ...ClaimsOptions) *Claims {
	claims := &Claims{
		issuer:   "default-Issuer",
		issuedAt: time.Now().Add(0).UTC(),
		exp:      time.Now().Add(0).UTC(),
		data:     make(map[string]interface{}),
	}

	for _, opt := range opts {
		opt(claims)
	}
	return claims
}

func AddClaim(key string, val interface{}) ClaimsOptions {
	return func(c *Claims) {
		c.data[key] = val
	}
}

func SetIssuer(val string) ClaimsOptions {
	return func(c *Claims) {
		c.issuer = val
	}
}

func SetSubject(val string) ClaimsOptions {
	return func(c *Claims) {
		c.subject = val
	}
}

func SetAudience(val string) ClaimsOptions {
	return func(c *Claims) {
		c.audience = val
	}
}

func SetExpiration(exp time.Time) ClaimsOptions {
	return func(c *Claims) {
		c.exp = exp
	}
}

func (j *JWT) Sign(claim Claims) ([]byte, error) {
	tok := jwt.New()

	_ = tok.Set(jwt.IssuerKey, claim.issuer)
	_ = tok.Set(jwt.IssuedAtKey, claim.issuedAt)
	_ = tok.Set(jwt.AudienceKey, claim.audience)
	_ = tok.Set(jwt.ExpirationKey, claim.exp)
	_ = tok.Set(jwt.SubjectKey, claim.subject)

	for key, val := range claim.data {
		_ = tok.Set(key, val)
	}

	return jwt.Sign(tok, jwt.WithKey(jwa.SignatureAlgorithm(j.algo), j.private_key))
}

func (j *JWT) Verify(tok string) (jwt.Token, error) {
	return jwt.Parse([]byte(tok), jwt.WithKey(j.algo, j.public_key))
}
