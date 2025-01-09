package auth

import (
	"github.com/go-chi/chi/v5"
)

type AuthProvider interface {
	Init(r chi.Router)
}
