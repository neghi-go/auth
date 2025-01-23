package tenant

import (
	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/iam/authentication/strategy"
	"github.com/neghi-go/iam/sessions"
)

func NewTenantStrategy() *strategy.Provider {
	return &strategy.Provider{
		Type: "multi-tenant",
		Init: func(r chi.Router, session sessions.Session) {

		},
	}
}
