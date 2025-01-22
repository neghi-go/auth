package oauth

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/auth/provider"
)

type Options func(*OauthProviderConfig)

type endpoint struct {
	token_url    string
	callback_url string
}
type OauthProviderConfig struct {
	provider     string
	clientID     string
	clientSecret string
	endpoint     endpoint
	scopes       []string
}

func New(cfg *OauthProviderConfig) *provider.Provider {
	return &provider.Provider{
		Type: cfg.provider + "-" + "oauth",
		Init: func(r chi.Router) {
			r.Get("/"+cfg.provider+"/authorize", authorize())
			r.Get("/"+cfg.provider+"/callback", callback())
		},
	}
}

func authorize() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {}
}

func callback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {}
}
