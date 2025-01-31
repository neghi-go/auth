package oauth2

import "github.com/neghi-go/iam/auth/providers"

func NewDummyProvider() *providers.Provider {
	return newOauthProvider("dummy")
}
