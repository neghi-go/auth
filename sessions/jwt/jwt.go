package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/neghi-go/iam/sessions"
	"github.com/neghi-go/iam/sessions/store"
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
	issuer      string
	audience    string
	expireTime  int64 //expiration time in seconds
	algo        Algo
	private_key *rsa.PrivateKey
	public_key  any

	token *jwt.Token

	store store.Store
}

func New(opts ...Options) (*JWT, error) {
	cfg := &JWT{
		algo:       RS256,
		issuer:     "default-issuer",
		audience:   "default-audience",
		expireTime: 3 * 60,
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

func SetIssuer(val string) Options {
	return func(j *JWT) {
		j.issuer = val
	}
}

func SetAudience(val string) Options {
	return func(j *JWT) {
		j.audience = val
	}
}

func SetExpiration(exp int64) Options {
	return func(j *JWT) {
		j.expireTime = exp
	}
}

func (j *JWT) Generate(w http.ResponseWriter, subject string, params ...interface{}) error {
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, j.issuer)
	_ = tok.Set(jwt.IssuedAtKey, time.Now().UTC())
	_ = tok.Set(jwt.AudienceKey, j.audience)
	_ = tok.Set(jwt.ExpirationKey, time.Now().Add(time.Second*time.Duration(j.expireTime)).UTC())
	_ = tok.Set(jwt.SubjectKey, subject)

	to, err := jwt.Sign(tok, jwt.WithKey(jwa.SignatureAlgorithm(j.algo), j.private_key))
	if err != nil {
		return err
	}
	w.Header().Set("Auth-Token", string(to))
	return nil
}

func (j *JWT) Verify(tok string) (jwt.Token, error) {
	return jwt.Parse([]byte(tok), jwt.WithKey(j.algo, j.public_key))
}

func (j *JWT) Validate(key string) error { return nil }

// DelField implements sessions.Session.
func (j *JWT) DelField(key string) error {
	panic("unimplemented")
}

// GetField implements sessions.Session.
func (j *JWT) GetField(key string) interface{} {
	panic("unimplemented")
}

// SetField implements sessions.Session.
func (j *JWT) SetField(key string, value interface{}) error {
	panic("unimplemented")
}

var _ sessions.Session = (*JWT)(nil)
