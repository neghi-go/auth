package password

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/database"
	"github.com/neghi-go/iam/auth/providers"
	"github.com/neghi-go/iam/models"
	"github.com/neghi-go/utilities"
	"golang.org/x/crypto/argon2"
)

var (
	errInvalidCredentials = errors.New("password: your email or password maybe incorrect")
	errInvalidToken       = errors.New("password: the verification token is invalid")
	errNotVerified        = errors.New("password: user is yet to be verified")
	errVerified           = errors.New("password: user is verified")
	errMismatchPasswords  = errors.New("password: passwords do not match")
)

type Action string

var (
	verify Action = "verify"
	resend Action = "resend"
	reset  Action = "reset"
	change Action = "change"
)

type PasswordProviderOptions func(*passwordProviderConfig)

type passwordProviderConfig struct {
	token_length int
	token_expiry time.Duration
	salt_length  int
	hash         Hasher
	notify       func(email, token string) error
	success      func(w http.ResponseWriter, status_code int, data interface{})
	error        func(w http.ResponseWriter, status utilities.ResponseStatus, err error, status_code int)
	store        database.Model[models.User]
}

func WithNotifier(notify func(email, token string) error) PasswordProviderOptions {
	return func(ppc *passwordProviderConfig) {
		ppc.notify = notify
	}
}

func WithStore(store database.Model[models.User]) PasswordProviderOptions {
	return func(ppc *passwordProviderConfig) {
		ppc.store = store
	}
}

func PasswordProvider(opts ...PasswordProviderOptions) *providers.Provider {
	cfg := &passwordProviderConfig{
		token_length: 6,
		token_expiry: time.Hour, // 1 hour
		salt_length:  16,        // length of generated password salt
		hash:         &argonHasher{},
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
		Name: "password",
		Init: func(r chi.Router, ctx providers.ProviderConfig) {
			r.Post("/authorize", func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Email    string `json:"email"`
					Password string `json:"password"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					cfg.error(w, utilities.ResponseError, err, http.StatusInternalServerError)
					return
				}
				//fetch user
				user, err := cfg.store.WithContext(r.Context()).
					Query(database.WithFilter("email", body.Email)).
					First()
				if err != nil {
					cfg.error(w, utilities.ResponseFail, errInvalidCredentials, http.StatusBadRequest)
					return
				}

				//check if user email is verified
				if !user.EmailVerified {
					cfg.error(w, utilities.ResponseFail, errNotVerified, http.StatusBadRequest)
					return
				}

				//validate Password
				if err := cfg.hash.compare(body.Password, user.PasswordSalt, user.Password); err != nil {
					cfg.error(w, utilities.ResponseFail, errInvalidCredentials, http.StatusBadRequest)
					return
				}
				//update user last login
				user.LastLogin = time.Now().UTC().Unix()
				if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
					Update(*user); err != nil {
					cfg.error(w, utilities.ResponseFail, err, http.StatusBadRequest)
					return
				}
				_ = ctx.Session.Generate(w, user.ID.String(), user.Email)
				cfg.success(w, http.StatusOK, user)

			})
			r.Post("/register", func(w http.ResponseWriter, r *http.Request) {
				action := Action(r.URL.Query().Get("action"))
				var body struct {
					Email    string `json:"email"`
					Password string `json:"password"`
					Repeat   string `json:"password_confirmation"`
					Token    string `json:"token"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					cfg.error(w, utilities.ResponseError, err, http.StatusInternalServerError)
					return
				}

				if body.Password != body.Repeat {
					cfg.error(w, utilities.ResponseFail, errMismatchPasswords, http.StatusBadRequest)
					return
				}
				switch action {
				case verify:
					//fetch user
					user, err := cfg.store.WithContext(r.Context()).
						Query(database.WithFilter("email", body.Email)).
						First()
					if err != nil {
						cfg.error(w, utilities.ResponseFail, errInvalidCredentials, http.StatusBadRequest)
						return
					}

					if user.EmailVerified {
						cfg.error(w, utilities.ResponseFail, errVerified, http.StatusBadRequest)
						return
					}

					if user.EmailVerifyToken != body.Token {
						cfg.error(w, utilities.ResponseFail, errInvalidToken, http.StatusBadRequest)
						return
					}

					if user.EmailVerifyTokenExpiresAt.Unix() < time.Now().UTC().Unix() {
						cfg.error(w, utilities.ResponseFail, errInvalidToken, http.StatusBadRequest)
						return
					}

					user.EmailVerifyToken = ""
					user.EmailVerifyTokenCreatedAt = time.Time{}
					user.EmailVerifyTokenExpiresAt = time.Time{}
					user.EmailVerified = true
					user.EmailVerifiedAt = time.Now().UTC()
					if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
						Update(*user); err != nil {
						cfg.error(w, utilities.ResponseFail, err, http.StatusBadRequest)
						return
					}
					cfg.success(w, http.StatusOK, nil)
					return
				case resend:
					//fetch user
					user, err := cfg.store.WithContext(r.Context()).
						Query(database.WithFilter("email", body.Email)).
						First()
					if err != nil {
						cfg.error(w, utilities.ResponseFail, errInvalidCredentials, http.StatusBadRequest)
						return
					}

					//check if user email is verified
					user.EmailVerifyToken = utilities.Generate(cfg.token_length)
					user.EmailVerifyTokenCreatedAt = time.Now().UTC()
					user.EmailVerifyTokenExpiresAt = time.Now().Add(time.Second * time.Duration(cfg.token_expiry.Seconds())).UTC()
					if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
						Update(*user); err != nil {
						cfg.error(w, utilities.ResponseFail, err, http.StatusBadRequest)
						return
					}
					if err := cfg.notify(user.Email, user.EmailVerifyToken); err != nil {
						cfg.error(w, utilities.ResponseFail, err, http.StatusBadRequest)
						return
					}
					cfg.success(w, http.StatusOK, nil)
					return
				default:
					//store validated user
					user := models.User{
						Email:                     body.Email,
						EmailVerifyToken:          utilities.Generate(cfg.token_length),
						EmailVerifyTokenCreatedAt: time.Now().UTC(),
						EmailVerifyTokenExpiresAt: time.Now().Add(time.Second * time.Duration(cfg.token_expiry.Seconds())).UTC(),

						PasswordSalt: utilities.Generate(cfg.salt_length),
					}

					//hash passwords
					hashedPassword := cfg.hash.hash(body.Password, user.PasswordSalt)
					user.Password = hashedPassword

					//persist user data
					if err := cfg.store.WithContext(r.Context()).Save(user); err != nil {
						cfg.error(w, utilities.ResponseError, err, http.StatusInternalServerError)
						return
					}

					//send notification with token
					if err := cfg.notify(user.Email, user.EmailVerifyToken); err != nil {
						cfg.error(w, utilities.ResponseError, err, http.StatusInternalServerError)
						return
					}
					cfg.success(w, http.StatusCreated, nil)
				}
			})
			r.Post("/change", func(w http.ResponseWriter, r *http.Request) {
				action := Action(r.URL.Query().Get("action"))
				var body struct {
					Email    string `json:"email"`
					Current  string `json:"current_password"`
					Password string `json:"password"`
					Repeat   string `json:"confirm_password"`
					Token    string `json:"token"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					cfg.error(w, utilities.ResponseError, err, http.StatusInternalServerError)
					return
				}
				user, err := cfg.store.WithContext(r.Context()).
					Query(database.WithFilter("email", body.Email)).First()
				if err != nil {
					cfg.error(w, utilities.ResponseFail, errInvalidCredentials, http.StatusBadRequest)
					return
				}

				if action == reset || action == resend {
					user.PasswordResetToken = utilities.Generate(cfg.token_length)
					user.PasswordResetTokenCreatedAt = time.Now().UTC()
					user.PasswordResetTokenExpiresAt = time.Now().Add(time.Second * time.Duration(cfg.token_expiry.Seconds()))
					if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
						Update(*user); err != nil {
						cfg.error(w, utilities.ResponseFail, errInvalidCredentials, http.StatusBadRequest)
						return
					}

					if err := cfg.notify(user.Email, user.PasswordResetToken); err != nil {
						cfg.error(w, utilities.ResponseFail, errInvalidCredentials, http.StatusBadRequest)
						return
					}
					cfg.success(w, http.StatusOK, nil)
					return
				}
				if action == change {
					if body.Password != body.Repeat {
						cfg.error(w, utilities.ResponseFail, errMismatchPasswords, http.StatusBadRequest)
						return
					}
					if err := cfg.hash.compare(body.Current, user.PasswordSalt, user.Password); err != nil {
						cfg.error(w, utilities.ResponseFail, errInvalidCredentials, http.StatusBadRequest)
						return
					}
					user.PasswordSalt = utilities.Generate(cfg.salt_length)
					user.Password = cfg.hash.hash(body.Password, user.PasswordSalt)
					user.PasswordUpdatedOn = time.Now().UTC()
					if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
						Update(*user); err != nil {
						cfg.error(w, utilities.ResponseError, err, http.StatusBadRequest)
						return
					}
					cfg.success(w, http.StatusOK, nil)
					return
				}
				if body.Token != user.PasswordResetToken {
					cfg.error(w, utilities.ResponseFail, errInvalidToken, http.StatusBadRequest)
					return
				}
				if time.Now().UTC().Unix() > user.PasswordResetTokenExpiresAt.Unix() {
					cfg.error(w, utilities.ResponseFail, errInvalidToken, http.StatusBadRequest)
					return
				}

				user.PasswordResetToken = ""
				user.PasswordSalt = utilities.Generate(cfg.salt_length)
				user.Password = cfg.hash.hash(body.Password, user.PasswordSalt)
				user.PasswordUpdatedOn = time.Now().UTC()
				user.PasswordResetTokenCreatedAt = time.Time{}
				user.PasswordResetTokenExpiresAt = time.Time{}

				if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
					Update(*user); err != nil {
					cfg.error(w, utilities.ResponseError, err, http.StatusBadRequest)
					return
				}
				cfg.success(w, http.StatusOK, nil)
			})
		},
	}
}

type Hasher interface {
	hash(password string, salt string) string
	compare(password, salt, compare string) error
}

type argonHasher struct{}

func (a *argonHasher) hash(password string, salt string) string {
	buf := argon2.IDKey([]byte(password), []byte(salt), 2, 19*1024, 1, 32)
	return base64.RawStdEncoding.EncodeToString(buf)
}
func (a *argonHasher) compare(password, salt, compare string) error {
	pass := a.hash(password, salt)
	if subtle.ConstantTimeCompare([]byte(pass), []byte(compare)) != 1 {
		return errors.New("passwords don't Match")
	}
	return nil
}
