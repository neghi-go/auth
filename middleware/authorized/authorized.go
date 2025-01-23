package authorized

import (
	"net/http"

	"github.com/neghi-go/iam/authorization"
)

type Options func(*Authorized)

type Authorized struct {
	enforcer *authorization.PolicyDecisionPoint
}

func New(opts ...Options) *Authorized {
	cfg := &Authorized{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func (a *Authorized) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = a.enforcer.Enforce(authorization.Attributes{})
		h.ServeHTTP(w, r)
	})
}

func WithEnforcer(e *authorization.PolicyDecisionPoint) Options {
	return func(a *Authorized) {
		a.enforcer = e
	}
}
