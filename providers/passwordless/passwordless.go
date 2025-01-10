package passwordless

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/auth"
)

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	LastLogin time.Time `json:"last_login"`
}

type PasswordlessProviderConfig struct {
}

func New(cfg *PasswordlessProviderConfig) *auth.Provider {
	return &auth.Provider{
		Type: "magic-link",
		Init: func(r chi.Router) {
			r.Post("/magic-link/authorize", authorize())
		},
	}
}

func authorize() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {}
}
