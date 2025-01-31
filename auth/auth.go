package auth

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/database/mongodb"
	"github.com/neghi-go/iam/auth/providers"
	"github.com/neghi-go/iam/internal/models"
	"github.com/neghi-go/session"
)

type Options func(*Auth)

type Auth struct {
	database, url string
	providers     []*providers.Provider
	session       session.Session
}

func New(opts ...Options) *Auth {
	cfg := &Auth{
		session: session.NewJWTSession(),
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func RegisterStrategy(provider ...*providers.Provider) Options {
	return func(a *Auth) {
		a.providers = provider
	}
}

func RegisterSession(session session.Session) Options {
	return func(a *Auth) {
		a.session = session
	}
}
func SetDatabase(url, database string) Options {
	return func(a *Auth) {
		a.database = database
		a.url = url
	}
}

func (a *Auth) Build() (chi.Router, error) {
	r := chi.NewRouter()

	mgd, err := mongodb.New(a.url, a.database)
	if err != nil {
		return nil, err
	}

	userModel, err := mongodb.RegisterModel(mgd, "auth_users", models.User{})
	if err != nil {
		return nil, err
	}

	for _, p := range a.providers {
		//Creates a new router for provider
		router := chi.NewRouter()
		// create a context value
		router.Use(func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				//Create new request with context value
				r.WithContext(context.WithValue(r.Context(), "provider", p.Name))
				h.ServeHTTP(w, r)
			})
		})
		//initialize route with context
		p.Init(router, &providers.ProviderConfig{
			Session: a.session,
			User:    userModel,
		})
		//register handler to global router
		r.Mount("/"+p.Name, router)
	}
	return r, nil
}
