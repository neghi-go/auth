package authorized

import "net/http"

type Options func(*Authorized)

type Authorized struct{}

func New(opts ...Options) *Authorized {
	cfg := &Authorized{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func (a *Authorized) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	})
}
