package passwordless

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/neghi-go/database"
	"github.com/neghi-go/iam/auth/models"
	"github.com/neghi-go/iam/auth/providers"
	"github.com/neghi-go/utilities"
)

var (
	errInvalidCredentials = errors.New("password: your email or password maybe incorrect")
	errInvalidToken       = errors.New("password: the verification token is invalid")
	errNotVerified        = errors.New("password: user is yet to be verified")
	errVerified           = errors.New("password: user is verified")
)

type Action string

const (
	authenticate Action = "authenticate"
	resend       Action = "resend"
)

type Option func(*passwordlessProviderConfig)

type passwordlessProviderConfig struct {
	store   database.Model[models.User]
	notify  func(email string, token string) error
	success func(w http.ResponseWriter, status_code int, data interface{})
	error   func(w http.ResponseWriter, status utilities.ResponseStatus, err error, status_code int)
}

func WithStore(model database.Model[models.User]) Option {
	return func(ppc *passwordlessProviderConfig) {
		ppc.store = model
	}
}

func WithNotifier(notifier func(email, token string) error) Option {
	return func(ppc *passwordlessProviderConfig) {
		ppc.notify = notifier
	}
}

func PasswordlessProvider(opts ...Option) *providers.Provider {
	cfg := &passwordlessProviderConfig{
		success: func(w http.ResponseWriter, status_code int, data interface{}) {
			utilities.JSON(w).SetStatus(utilities.ResponseSuccess).
				SetStatusCode(status_code).SetData(data).Send()
		},
		error: func(w http.ResponseWriter, status utilities.ResponseStatus, err error, status_code int) {
			utilities.JSON(w).SetStatus(status).SetStatusCode(status_code).
				SetMessage(err.Error()).Send()
		},
		notify: func(email, token string) error {
			fmt.Printf("email: %v, token: %v", email, token)
			return nil
		},
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return &providers.Provider{
		Name: "magic-link",
		Init: func(r chi.Router, ctx providers.ProviderConfig) {
			r.Post("/authorize", func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Email string `json:"email"`
					Token string `json:"token"`
				}
				action := r.URL.Query().Get("action")
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					cfg.error(w, utilities.ResponseError, err, http.StatusInternalServerError)
					return
				}

				switch Action(action) {
				case authenticate:

					if body.Token == "" {
						cfg.error(w, utilities.ResponseFail, errInvalidToken, http.StatusBadRequest)
						return
					}
					//when url contains token
					//parse token
					tokenValues, _ := utilities.Decrypt(body.Token)
					//validate parsed token
					if tokenValues["email"] != body.Email {
						cfg.error(w, utilities.ResponseFail, errInvalidToken, http.StatusBadRequest)
						return
					}
					timestamp, _ := tokenValues["expiry"].(int64)
					if time.Now().UTC().Unix() > timestamp {
						cfg.error(w, utilities.ResponseFail, errInvalidToken, http.StatusBadRequest)
						return
					}

					user, err := cfg.store.WithContext(r.Context()).
						Query(database.WithFilter("email", body.Email)).First()
					if err != nil {
						cfg.error(w, utilities.ResponseFail, errInvalidCredentials, http.StatusBadRequest)
						return
					}
					user.LastLogin = time.Now().UTC().Unix()
					if !user.EmailVerified {
						user.EmailVerified = true
						user.EmailVerifiedAt = time.Now().UTC()
					}
					// create session for user
					//create session, either JWT or Cookie and send to user
					err = ctx.Session.Generate(w, user.ID.String(), user.Email)
					if err != nil {
						cfg.error(w, utilities.ResponseFail, err, http.StatusBadRequest)
						return
					}

					//update user
					if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", body.Email)).
						Update(*user); err != nil {
						cfg.error(w, utilities.ResponseFail, err, http.StatusBadRequest)
						return

					}
					cfg.success(w, http.StatusOK, user)
				case resend:
					if _, err := cfg.store.WithContext(r.Context()).
						Query(database.WithFilter("email", body.Email)).First(); err != nil {
						cfg.error(w, utilities.ResponseFail, errInvalidCredentials, http.StatusBadRequest)
						return
					}
					tokenValues := map[string]any{
						"email":  body.Email,
						"expiry": time.Now().Add(time.Minute * 10).UTC().Unix(),
					}
					token, _ := utilities.Encrypt(tokenValues)
					// send to user
					if err := cfg.notify(body.Email, token); err != nil {
						cfg.error(w, utilities.ResponseError, err, http.StatusInternalServerError)
						return
					}
				default:
					//get user if it exist and generate session
					if _, err := cfg.store.WithContext(r.Context()).
						Query(database.WithFilter("email", body.Email)).First(); err != nil {
						user := models.User{
							ID:    uuid.New(),
							Email: body.Email,
						}
						if err := cfg.store.WithContext(r.Context()).Save(user); err != nil {
							cfg.error(w, utilities.ResponseError, err, http.StatusBadRequest)
							return
						}
					}
					tokenValues := map[string]any{
						"email":  body.Email,
						"expiry": time.Now().Add(time.Minute * 10).UTC().Unix(),
					}
					token, _ := utilities.Encrypt(tokenValues)
					if err := cfg.notify(body.Email, token); err != nil {
						cfg.error(w, utilities.ResponseError, err, http.StatusInternalServerError)
						return
					}

					cfg.success(w, http.StatusOK, nil)
				}

			})
		},
	}
}
