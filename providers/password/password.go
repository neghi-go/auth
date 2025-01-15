package password

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/auth"
	"github.com/neghi-go/auth/internal/models"
	"github.com/neghi-go/database"
	"github.com/neghi-go/utilities"
	"golang.org/x/crypto/argon2"
)

type Action string

const (
	verify Action = "verify"
	resend Action = "resend"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ResetPasswordRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Option func(*PasswordProviderConfig)

type PasswordProviderConfig struct {
	hash    Hasher
	store   database.Model[models.User]
	notify  func(email, token string) error
	encrypt *auth.Encrypt
}

func Config(opts ...Option) *PasswordProviderConfig {
	cfg := &PasswordProviderConfig{
		hash: &argonHasher{},
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}

func New(cfg *PasswordProviderConfig) *auth.Provider {
	return &auth.Provider{
		Type: "password",
		Init: func(r chi.Router) {
			r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
				action := r.URL.Query().Get("action")
				var body loginRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseError).
						SetStatusCode(http.StatusInternalServerError).
						SetMessage(err.Error()).
						Send()
					return
				}
				//fetch user
				user, err := cfg.store.WithContext(r.Context()).
					Filter(database.SetParams(database.SetFilter("email", body.Email))).
					First()
				if err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseFail).
						SetStatusCode(http.StatusBadRequest).
						SetMessage(err.Error()).
						Send()
					return
				}

				//check if user email is verified
				if !user.EmailVerified {
					action = string(verify)
				}

				switch Action(action) {
				case verify:
					token := utilities.Generate(4)

					user.EmailVerifyToken = token
					user.EmailVerifyTokenExpiresAt = time.Now().Add(time.Hour * 2).UTC()

					if err := cfg.store.UpdateOne(*user); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}
					if err := cfg.notify(user.Email, token); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}
					utilities.JSON(w).
						SetStatus(utilities.ResponseSuccess).
						SetStatusCode(http.StatusOK).
						SetMessage("your email is yet to be verified, please check your email for verification code").
						Send()
				case resend:
					token := utilities.Generate(4)

					user.EmailVerifyToken = token
					user.EmailVerifyTokenExpiresAt = time.Now().Add(time.Hour * 2).UTC()

					if err := cfg.store.UpdateOne(*user); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}
					if err := cfg.notify(user.Email, token); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}
					utilities.JSON(w).
						SetStatus(utilities.ResponseSuccess).
						SetStatusCode(http.StatusOK).
						SetMessage("your verification code has been resent").
						Send()
				default:
					//validate Password
					if err := cfg.hash.compare(body.Password, user.PasswordSalt, user.Password); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}

					//create session, either JWT or Cookie and send to user

					utilities.JSON(w).
						SetStatus(utilities.ResponseSuccess).
						SetStatusCode(http.StatusOK).
						SetMessage("successfull login attempt").
						SetData(user).
						Send()
				}

			})
			r.Post("/register", func(w http.ResponseWriter, r *http.Request) {})
			r.Post("/password-reset", func(w http.ResponseWriter, r *http.Request) {})
			r.Post("/email-verify", func(w http.ResponseWriter, r *http.Request) {})
		},
	}
}

type Hasher interface {
	hash(password string, salt string) string
	compare(password, salt, compare string) error
}

type argonHasher struct{}

func (a *argonHasher) hash(password string, salt string) string {
	return string(argon2.IDKey([]byte(password), []byte(salt), 2, 19*1024, 1, 32))
}
func (a *argonHasher) compare(password, salt, compare string) error {
	pass := argon2.IDKey([]byte(password), []byte(salt), 2, 19*1024, 1, 32)
	if subtle.ConstantTimeCompare(pass, []byte(compare)) != 1 {
		return errors.New("passwords don't Match")
	}
	return nil
}
