package providers

import (
	"github.com/neghi-go/iam/authentication/strategy"
	"github.com/neghi-go/iam/authentication/strategy/oauth"
)

func GoogleProvider(opts ...oauth.Options) *strategy.Provider {
	cfg := &oauth.OauthProviderConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return oauth.New(cfg)
}
