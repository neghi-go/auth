package password

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type PasswordProvider[T any] struct {
	hash Hasher
}

func New[T any]() *PasswordProvider[T] {
	return &PasswordProvider[T]{}
}

func (p *PasswordProvider[T]) Init(r chi.Router) {
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			panic(err)
		}
		password := r.FormValue("password")

		err = p.hash.compare(password, "")
		if err != nil {
			panic(err)
		}

		//create s4ession

		//return user
		w.WriteHeader(http.StatusOK)

	})
	r.Post("/register", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		switch token {
		case "":
		default:
		}
	})
	r.Post("/reset-password", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		switch token {
		case "":
		default:
		}
	})
	r.Post("/logout", func(w http.ResponseWriter, r *http.Request) {})
}

type Hasher interface {
	hash(password string, salt int) (string, error)
	compare(password, compare string) error
}
