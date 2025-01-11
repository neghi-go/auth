package auth

type Options func(*Auth)

type Auth struct {
	secret    string
	providers map[string]Provider
}

func New(opts ...Options) *Auth {
	cfg := &Auth{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func RegisterProvider(name string, provider Provider) Options {
	return func(a *Auth) {
		a.providers[name] = provider
	}
}

func WithSecret(secret string) Options {
	return func(a *Auth) {
		a.secret = secret
	}
}
