package passwordless

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type PasswordlessProvider[T any] struct {
	prefix string
}

func (p *PasswordlessProvider[T]) Init(r chi.Router) {
	r.Post(p.prefix+"/authenticate", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			panic(err)
		}

		//send login link
		w.WriteHeader(http.StatusOK)
	})
	r.Post(p.prefix+"/login", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")

		if token == "" {
			panic(errors.New("panic"))
		}
	})
}
