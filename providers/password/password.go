package password

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/auth"
)

type Option func(*PasswordProviderConfig)

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	LastLogin time.Time `json:"last_login"`
}

type PasswordProviderConfig struct {
	login    func(w http.ResponseWriter, r *http.Request)
	register func(w http.ResponseWriter, r *http.Request)
	reset    func(w http.ResponseWriter, r *http.Request)
	logout   func(w http.ResponseWriter, r *http.Request)
	hash     Hasher
}

func Config(opts ...Option) *PasswordProviderConfig {
	cfg := &PasswordProviderConfig{
		login:    login,
		register: register,
		reset:    reset,
		logout:   logout,
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
			r.Post("/password/login", cfg.login)
			r.Post("/password/register", cfg.register)
			r.Post("/password/reset-password", cfg.reset)
			r.Post("/logout", cfg.logout)
		},
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		panic(err)
	}

	//create s4ession

	//return user
	w.WriteHeader(http.StatusOK)
}

func register(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	switch token {
	case "":
	default:
	}
}

func logout(w http.ResponseWriter, r *http.Request) {

}

func reset(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	switch token {
	case "":
	default:
	}
}

type Hasher interface {
	hash(password string, salt int) (string, error)
	compare(password, compare string) error
}
