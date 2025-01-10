package oauth

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/auth"
)

type endpoint struct {
	token_url string
}
type OauthProviderConfig struct {
	provider     string
	clientID     string
	clientSecret string
	endpoint     endpoint
	authorize    func(w http.ResponseWriter, r *http.Request)
	callback     func(w http.ResponseWriter, r *http.Request)
}

func New(cfg *OauthProviderConfig) *auth.Provider {
	return &auth.Provider{
		Type: cfg.provider + "-" + "oauth",
		Init: func(r chi.Router) {
			r.Get("/"+cfg.provider+"/authorize", cfg.authorize)
			r.Get("/"+cfg.provider+"/callback", cfg.callback)
		},
	}
}
