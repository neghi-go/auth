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
	store storage.Store
}

func New(cfg *PasswordlessProviderConfig) *auth.Provider {
	return &auth.Provider{
		Type: "magic-link",
		Init: func(r chi.Router) {
			r.Post("/magic-link/authorize", authorize(cfg.store))
		},
	}
}

func authorize(store storage.Store) http.HandlerFunc {
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
			//validate parsed token
			// create session for user
			res.SetStatus(utilities.ResponseSuccess).
				SetStatusCode(http.StatusOK).
				Send()
		case resend:
			//regenerate session/jwt token
			if _, err := store.Get(r.Context(), email); err != nil {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					Send()
				return
			}

			//create validation code.
			// send to user
			res.SetStatus(utilities.ResponseSuccess).
				SetStatusCode(http.StatusOK).
				Send()
		default:
			//get user if it exist and generate session
			if _, err := store.Get(r.Context(), email); err != nil {
				if errors.Is(err, errors.New("doc not found")) {
					if err := store.Set(r.Context(), []byte("")); err != nil {
						res.SetStatus(utilities.ResponseError).
							SetStatusCode(http.StatusBadRequest).
							Send()
						return
					}
				}
			}

			//create session code and send email or console.log.

			res.SetStatus(utilities.ResponseSuccess).
				SetStatusCode(http.StatusOK).
				Send()
		}
	}
}
