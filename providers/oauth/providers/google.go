package providers

import (
	"github.com/neghi-go/auth"
	"github.com/neghi-go/auth/providers/oauth"
)

func GoogleProvider() *auth.Provider {
	return oauth.New(&oauth.OauthProviderConfig{})
}
