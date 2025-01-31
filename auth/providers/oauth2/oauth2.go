package oauth2

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/iam/auth/providers"
	"github.com/neghi-go/utilities"
)

type OauthOptions func(*oauthConfig)

func withEndpoint(token_url, auth_url string) OauthOptions {
	return func(oc *oauthConfig) {
		oc.endpoint.token_url = token_url
		oc.endpoint.authorization_url = auth_url
	}
}

func ClientID(client_id string) OauthOptions {
	return func(oc *oauthConfig) {
		oc.client_id = client_id
	}
}
func ClientSecret(secret string) OauthOptions {
	return func(oc *oauthConfig) {
		oc.client_secret = secret
	}
}

func Scopes(scopes []string) OauthOptions {
	return func(oc *oauthConfig) {
		oc.scope = scopes
	}
}

func UsePKCE(use bool) OauthOptions {
	return func(oc *oauthConfig) {
		oc.usePKCE = use
	}
}

type oauthConfig struct {
	client_id     string
	client_secret string
	endpoint      struct {
		token_url         string
		authorization_url string
	}
	scope           []string
	usePKCE         bool
	auth_url_value  func(c *oauthConfig) url.Values
	token_url_value func(c *oauthConfig) url.Values
}

func AuthUrlValues(f func(c *oauthConfig) url.Values) OauthOptions {
	return func(oc *oauthConfig) {
		oc.auth_url_value = f
	}
}

func TokenUrlValues(f func(c *oauthConfig) url.Values) OauthOptions {
	return func(oc *oauthConfig) {
		oc.auth_url_value = f
	}
}

func newOauthProvider(name string, opts ...OauthOptions) *providers.Provider {
	cfg := &oauthConfig{
		client_id:     "test_id",
		client_secret: "test-secret",
		endpoint: struct {
			token_url         string
			authorization_url string
		}{
			authorization_url: "https://dummy.com/auth",
			token_url:         "https://dummy.com/token",
		},
		scope:   []string{"read", "write"},
		usePKCE: true,
		auth_url_value: func(c *oauthConfig) url.Values {
			verifier := generateVerifier(32)
			challenge := generateChallenge(verifier, base64_encoding, s256)
			v := url.Values{
				"client_id":             {c.client_id},
				"state":                 {verifier},
				"response_type":         {"code"},
				"scope":                 {strings.Join(c.scope, " ")},
				"code_challenge":        {challenge},
				"code_challenge_method": {string(s256)},
			}
			return v
		},
		token_url_value: func(c *oauthConfig) url.Values {
			v := url.Values{
				"client_id":     {c.client_id},
				"client_secret": {c.client_secret},
				"grant_type":    {"authorization_code"},
			}

			return v
		},
	}

	for _, opt := range opts {
		opt(cfg)
	}
	return &providers.Provider{
		Name: name,
		Init: func(r chi.Router, ctx *providers.ProviderConfig) {
			r.Get("/authorize", func(w http.ResponseWriter, r *http.Request) {
				var buf bytes.Buffer
				url := strings.Split(r.RequestURI, "/")
				url[len(url)-1] = "callback"

				buf.WriteString(cfg.endpoint.authorization_url)
				buf.WriteString("?")
				v := cfg.auth_url_value(cfg)
				v.Add("redirect_uri", "http://"+r.Host+strings.Join(url, "/"))
				buf.WriteString(v.Encode())

				//utilities.JSON(w).SetStatus(utilities.ResponseSuccess).SetStatusCode(http.StatusOK).
				//SetData(map[string]string{"auth_url": buf.String()}).Send()
				http.Redirect(w, r, buf.String(), http.StatusTemporaryRedirect)

			})
			r.Get("/callback", func(w http.ResponseWriter, r *http.Request) {
				code := r.URL.Query().Get("code")
				state := r.URL.Query().Get("state")
				url := strings.Split(r.RequestURI, "/")
				url[len(url)-1] = "callback"

				v := cfg.token_url_value(cfg)
				v.Add("redirect_uri", "http://"+r.Host+strings.Join(url, "/"))
				v.Add("code", code)
				v.Add("code_verifier", state)

				res, err := http.PostForm(cfg.endpoint.token_url, v)
				if err != nil {
					utilities.JSON(w).SetStatus(utilities.ResponseError).
						SetStatusCode(http.StatusInternalServerError).SetMessage(err.Error()).Send()
					return
				}

				defer res.Body.Close()

				var response map[string]interface{}
				if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
					utilities.JSON(w).SetStatus(utilities.ResponseError).SetStatusCode(http.StatusBadRequest).Send()
					return
				}
				utilities.JSON(w).SetStatus(utilities.ResponseSuccess).SetStatusCode(http.StatusOK).SetData(response).Send()
			})
		},
	}
}
