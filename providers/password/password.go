package password

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/auth"
	"github.com/neghi-go/auth/storage"
	"github.com/neghi-go/utilities"
	_ "golang.org/x/crypto/argon2"
	_ "golang.org/x/crypto/bcrypt"
	_ "golang.org/x/crypto/scrypt"
)

type Action string

const (
	resend   Action = "resend"
	validate Action = "validate"
)

type Option func(*PasswordProviderConfig)

type User struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	LastLogin int64  `json:"last_login"`
}

type PasswordProviderConfig struct {
	hash    Hasher
	store   storage.Store
	notify  func(email, token string) error
	encrypt *auth.Encrypt
}

func Config(opts ...Option) *PasswordProviderConfig {
	cfg := &PasswordProviderConfig{}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}

func New(cfg *PasswordProviderConfig) *auth.Provider {
	return &auth.Provider{
		Type: "password",
		Init: func(r chi.Router) {
			r.Post("/password/login", login(cfg))
			r.Post("/password/register", register(cfg))
			r.Post("/password/reset-password", reset())
			r.Post("/logout", logout())
		},
	}
}

func login(cfg *PasswordProviderConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := utilities.JSON(w)
		err := r.ParseForm()
		if err != nil {
			res.
				SetStatus(utilities.ResponseError).
				SetStatusCode(http.StatusBadRequest).
				Send()
		}

		email := r.Form.Get("email")
		password := r.Form.Get("password")

		data, err := cfg.store.Get(r.Context(), email)

		user := User{}
		err = auth.GobDecode(data, &user)
		if err != nil {
			res.
				SetStatus(utilities.ResponseError).
				SetStatusCode(http.StatusBadRequest).
				Send()
		}

		err = cfg.hash.compare(password, user.Password)
		if err != nil {
			res.
				SetStatus(utilities.ResponseError).
				SetStatusCode(http.StatusBadRequest).
				Send()
		}

		user.LastLogin = time.Now().UTC().Unix()
		b, _ := auth.GobEncode(user)
		err = cfg.store.Set(r.Context(), b)
		if err != nil {
			res.
				SetStatus(utilities.ResponseError).
				SetStatusCode(http.StatusBadRequest).
				Send()
		}

		//create session either jwt  or cookie

		res.SetStatus(utilities.ResponseSuccess).
			SetStatusCode(http.StatusOK).
			SetData(user).
			Send()
	}
}

func register(cfg *PasswordProviderConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		action := r.URL.Query().Get("action")
		res := utilities.JSON(w)
		err := r.ParseForm()
		if err != nil {
			res.
				SetStatus(utilities.ResponseError).
				SetStatusCode(http.StatusBadRequest).
				Send()
		}

		switch Action(action) {
		case validate:
			email := r.Form.Get("email")
			_, err := cfg.store.Get(r.Context(), email)
			if err != nil {
				res.
					SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					Send()
			}
			tokenValue := map[string]any{
				"email":  email,
				"expiry": time.Now().Add(time.Minute * 10).UTC().Unix(),
			}
			token, _ := cfg.encrypt.Encrypt(tokenValue)

			_ = cfg.notify(email, token)

			res.SetStatus(utilities.ResponseSuccess).
				SetStatusCode(http.StatusOK).
				Send()

		case resend:
			email := r.Form.Get("email")
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
			token := r.URL.Query().Get("token")
			if token == "" {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					Send()
			}
			password := r.Form.Get("password")

			tokenValues, _ := cfg.encrypt.Decrypt(token)
			//validate parsed token
			timestamp, _ := tokenValues["expiry"].(int64)
			if time.Now().UTC().Unix() > timestamp {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					SetMessage("validation token has expire, please try again").
					Send()
				return
			}
			email, _ := tokenValues["email"].(string)

			user := User{
				Email:     email,
				Password:  password,
				LastLogin: time.Now().UTC().Unix(),
			}

			u, _ := auth.GobEncode(user)

			err = cfg.store.Set(r.Context(), u)
			if err != nil {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					Send()
				return
			}

			// create  either jwt  or cookie session

			res.SetStatus(utilities.ResponseSuccess).
				SetStatusCode(http.StatusOK).
				SetData(user).
				Send()
		}
	}
}

func logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {}
}

func reset() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {}
}

type Hasher interface {
	hash(password string, salt int) (string, error)
	compare(password, compare string) error
}

type ArgonHasher struct {
}

func (a *ArgonHasher) hash(password string, salt int) (string, error) {
	return "", nil
}
func (a *ArgonHasher) compare(password string, compare string) error {
	return nil
}
