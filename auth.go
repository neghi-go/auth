package auth

import "github.com/go-chi/chi/v5"

type Options func(*Auth)

type Auth struct {
	providers []*Provider
	router    chi.Router
}

func New(opts ...Options) *Auth {
	cfg := &Auth{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func RegisterProvider(provider *Provider) Options {
	return func(a *Auth) {
		a.providers = append(a.providers, provider)
	}
}

func (a *Auth) Build() error {
	for _, p := range a.providers {
		p.Init(a.router)
	}
	return nil
}
