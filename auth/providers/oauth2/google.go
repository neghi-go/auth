package oauth2

import "github.com/neghi-go/iam/auth/providers"

func NewGoogleProvider(opts ...OauthOptions) *providers.Provider {
	opts = append(opts, withEndpoint("https://oauth2.googleapis.com/token", "https://accounts.google.com/o/oauth2/v2/auth"))
	return newOauthProvider("google", opts...)
}
