package session

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
	"github.com/neghi-go/session/store"
)

type Algo string

const (
	rs256 Algo = "RS256"
	hs256 Algo = "HS256"
)

var (
	ErrPrivateKeyEmpty = errors.New("empty private key")
	ErrPublicKeyEmpty  = errors.New("empty public key")
)

func (a Algo) String() string {
	return string(a)
}

type JWTOptions func(*JWT)

type JWT struct {
	issuer      string
	audience    string
	expireTime  int64 //expiration time in seconds
	algo        Algo
	private_key *rsa.PrivateKey
	public_key  any

	access_token  jwt.Token
	refresh_token jwt.Token

	token jwt.Token

	secret []byte

	store store.Store
}

func NewJWTSession(opts ...JWTOptions) *JWT {
	cfg := &JWT{
		algo:       hs256,
		issuer:     "default-issuer",
		audience:   "default-audience",
		expireTime: 3 * 60,
		secret:     []byte("default-secret"),
	}

	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// WithRS256 expects a base64 encoded string of the
// private key and public key
func WithRSA256(private_key, public_key string) JWTOptions {
	pri, _ := base64.StdEncoding.DecodeString(private_key)
	priblock, _ := pem.Decode(pri)
	privateKey, _ := x509.ParsePKCS1PrivateKey(priblock.Bytes)
	pub, _ := base64.StdEncoding.DecodeString(public_key)
	pubblock, _ := pem.Decode(pub)
	publicKey, _ := x509.ParsePKIXPublicKey(pubblock.Bytes)
	return func(j *JWT) {
		j.algo = rs256
		j.private_key = privateKey
		j.public_key = publicKey
	}
}

func WithSecret(secret string) JWTOptions {
	return func(j *JWT) {
		j.algo = hs256
		j.secret = []byte(secret)
	}
}

func SetIssuer(val string) JWTOptions {
	return func(j *JWT) {
		j.issuer = val
	}
}

func SetAudience(val string) JWTOptions {
	return func(j *JWT) {
		j.audience = val
	}
}

func SetExpiration(exp int64) JWTOptions {
	return func(j *JWT) {
		j.expireTime = exp
	}
}

func (j *JWT) Generate(w http.ResponseWriter, subject string, params ...interface{}) error {
	var secret any
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, j.issuer)
	_ = tok.Set(jwt.IssuedAtKey, time.Now().UTC())
	_ = tok.Set(jwt.AudienceKey, j.audience)
	_ = tok.Set(jwt.ExpirationKey, time.Now().Add(time.Second*time.Duration(j.expireTime)).UTC())
	_ = tok.Set(jwt.SubjectKey, subject)

	if j.algo == rs256 {
		secret = j.private_key
	} else {
		secret = j.secret
	}

	to, err := jwt.Sign(tok, jwt.WithKey(jwa.SignatureAlgorithm(j.algo), secret))
	if err != nil {
		return err
	}
	w.Header().Set("Auth-Token", string(to))
	return nil
}

func (j *JWT) Verify(tok string) (jwt.Token, error) {
	var secret any
	if j.algo == rs256 {
		secret = j.public_key
	} else {
		secret = j.secret
	}
	return jwt.Parse([]byte(tok), jwt.WithKey(j.algo, secret))
}

func (j *JWT) Validate(key string) error { return nil }

// DelField implements sessions.Session.
func (j *JWT) DelField(key string) error {
	return j.token.Remove(key)
}

// GetField implements sessions.Session.
func (j *JWT) GetField(key string) interface{} {
	if value, ok := j.token.Get(key); ok {
		return value
	}
	return nil
}

// SetField implements sessions.Session.
func (j *JWT) SetField(key string, value interface{}) error {
	return j.token.Set(key, value)
}

var _ Session = (*JWT)(nil)
