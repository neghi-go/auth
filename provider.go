package auth

import (
	"github.com/go-chi/chi/v5"
)

type Provider struct {
	Type string
	Init func(r chi.Router)
}
