package providers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/iam/auth/storage"
	"github.com/neghi-go/session"
)

type ProviderConfig struct {
	Session session.Session
	Store   storage.Storage
	Success func(w http.ResponseWriter, data interface{})
	Set     func()
	Unset   func()
}
type Provider struct {
	Name string
	Init func(r chi.Router, ctx ProviderConfig)
}
