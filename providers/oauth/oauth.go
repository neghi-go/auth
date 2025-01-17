package oauth

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/auth"
)

type Oauth struct {
	AccessToken  string                 `json:"access_token"`
	RefreshToken string                 `json:"refresh_token"`
	IDToken      string                 `json:"id_token"`
	Data         map[string]interface{} `json:"data"`
}

type endpoint struct {
	token_url string
}
type OauthProviderConfig struct {
	provider     string
	clientID     string
	clientSecret string
	endpoint     endpoint
}

func New(cfg *OauthProviderConfig) *auth.Provider {
	return &auth.Provider{
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
