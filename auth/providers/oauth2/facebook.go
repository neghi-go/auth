package oauth2

import "github.com/neghi-go/iam/auth/providers"

func NewFacebookProvider(opts ...OauthOptions) *providers.Provider {
	return newOauthProvider("facebook", opts...)
}
