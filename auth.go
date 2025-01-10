package auth

type Options func(*Auth)

type Auth struct {
	providers map[string]Provider
}

func New(opts ...Options) *Auth {
	return &Auth{}
}
