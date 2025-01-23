package providers

import (
	"github.com/neghi-go/iam/authentication/provider"
	"github.com/neghi-go/iam/authentication/provider/oauth"
)

func GoogleProvider(opts ...oauth.Options) *provider.Provider {
	cfg := &oauth.OauthProviderConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return oauth.New(cfg)
}
