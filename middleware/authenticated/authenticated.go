package authenticated

import "net/http"

type Options func(*Authenticated)

type Authenticated struct {
}

func New(opts ...Options) *Authenticated {
	cfg := &Authenticated{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func (i *Authenticated) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	})
}
