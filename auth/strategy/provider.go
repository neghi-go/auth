package strategy

import (
	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/iam/auth/sessions"
)

type Provider struct {
	Type string
	Init func(r chi.Router, session sessions.Session)
}
