package passwordless

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/auth"
	"github.com/neghi-go/auth/storage"
	"github.com/neghi-go/utilities"
)

type Action string

const (
	authenticate Action = "authenticate"
	resend       Action = "resend"
)

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	LastLogin time.Time `json:"last_login"`
}

type PasswordlessProviderConfig struct {
	store   storage.Store
	notify  func(email string, token string) error
	encrypt *auth.Encrypt
}

func New(cfg *PasswordlessProviderConfig) *auth.Provider {
	return &auth.Provider{
		Type: "magic-link",
		Init: func(r chi.Router) {
			r.Post("/magic-link/authorize", authorize(cfg))
		},
	}
}

func authorize(cfg *PasswordlessProviderConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := utilities.JSON(w)
		action := r.URL.Query().Get("action")

		if err := r.ParseForm(); err != nil {
			res.SetStatus(utilities.ResponseError).
				SetStatusCode(http.StatusBadRequest).
				Send()
			return
		}

		email := r.Form.Get("email")

		switch Action(action) {
		case authenticate:
			token := r.URL.Query().Get("token")

			if token == "" {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					Send()
				return
			}
			//when url contains token
			//parse token
			tokenValues, _ := cfg.encrypt.Decrypt(token)
			//validate parsed token
			if tokenValues["email"] != email {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					Send()
				return
			}
			timestamp, _ := tokenValues["expiry"].(int64)
			if time.Now().UTC().Unix() > timestamp {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					SetMessage("validation token has expire, please try again").
					Send()
				return
			}

			if _, err := cfg.store.Get(r.Context(), email); err != nil {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					Send()
				return
			}
			// create session for user
			res.SetStatus(utilities.ResponseSuccess).
				SetStatusCode(http.StatusOK).
				Send()
		case resend:
			if _, err := cfg.store.Get(r.Context(), email); err != nil {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					Send()
				return
			}
			tokenValues := map[string]any{
				"email":  email,
				"expiry": time.Now().Add(time.Minute * 10).UTC().Unix(),
			}
			token, _ := cfg.encrypt.Encrypt(tokenValues)
			// send to user
			_ = cfg.notify(email, token)
			res.SetStatus(utilities.ResponseSuccess).
				SetStatusCode(http.StatusOK).
				Send()
		default:
			//get user if it exist and generate session
			if _, err := cfg.store.Get(r.Context(), email); err != nil {
				if errors.Is(err, errors.New("doc not found")) {
					if err := cfg.store.Set(r.Context(), []byte("")); err != nil {
						res.SetStatus(utilities.ResponseError).
							SetStatusCode(http.StatusBadRequest).
							Send()
						return
					}
				}
			}
			tokenValues := map[string]any{
				"email":  email,
				"expiry": time.Now().Add(time.Minute * 10).UTC().Unix(),
			}
			token, _ := cfg.encrypt.Encrypt(tokenValues)
			_ = cfg.notify(email, token)
			res.SetStatus(utilities.ResponseSuccess).
				SetStatusCode(http.StatusOK).
				Send()
		}
	}
}
