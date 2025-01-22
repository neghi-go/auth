package cookies

import (
	"net/http"
	"time"
)

var (
	SameSiteLax     SameSite = "lax"
	SameSiteStrict  SameSite = "strict"
	SameSiteNone    SameSite = "none"
	SameSiteDefault SameSite = "default"
)

type SameSite string

func (s SameSite) String() string {
	return string(s)
}

type Options func(*Cookie)

type Cookie struct {
	name     string
	value    string
	path     string
	domain   string
	sameSite SameSite
	secure   bool
	httpOnly bool
	maxAge   time.Duration
}

func WithName(name string) Options {
	return func(c *Cookie) {
		c.name = name
	}
}

func WithValue(value string) Options {
	return func(c *Cookie) {
		c.value = value
	}
}

func WithPath(path string) Options {
	return func(c *Cookie) {
		c.path = path
	}
}

func WithDomain(domain string) Options {
	return func(c *Cookie) {
		c.domain = domain
	}
}

func WithSameSite(samesite SameSite) Options {
	return func(c *Cookie) {
		c.sameSite = samesite
	}
}

func WithSecure(secure bool) Options {
	return func(c *Cookie) {
		c.secure = secure
	}
}

func WithHTTPOnly(http_only bool) Options {
	return func(c *Cookie) {
		c.httpOnly = http_only
	}
}

func WithMaxAge(max_age time.Duration) Options {
	return func(c *Cookie) {
		c.maxAge = max_age
	}
}

func New(opts ...Options) *Cookie {
	cfg := &Cookie{
		name:     "default-name",
		value:    "default-value",
		path:     "/",
		domain:   "/",
		sameSite: SameSiteLax,
		secure:   false,
		httpOnly: true,
		maxAge:   0,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func (c *Cookie) SetCookie(w http.ResponseWriter) {
	var val http.SameSite
	switch c.sameSite {
	case SameSiteLax:
		val = http.SameSiteLaxMode
	case SameSiteNone:
		val = http.SameSiteNoneMode
	case SameSiteStrict:
		val = http.SameSiteStrictMode
	default:
		val = http.SameSiteDefaultMode
	}
	cookie := &http.Cookie{
		Name:     c.name,
		Value:    c.value,
		Domain:   c.domain,
		Path:     c.path,
		Secure:   c.secure,
		HttpOnly: c.httpOnly,
		MaxAge:   int(c.maxAge.Seconds()),
		SameSite: val,
	}
	http.SetCookie(w, cookie)
}
