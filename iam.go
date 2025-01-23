package iam

import (
	"github.com/casbin/casbin/v2"
	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/iam/authentication"
	"github.com/neghi-go/iam/authentication/strategy/password"
)

type Options func(*IAM)

type IAM struct {
	auth *authentication.Auth
	acl  *casbin.Enforcer
}

func New(r chi.Router, opts ...Options) (*IAM, error) {
	cas, err := casbin.NewEnforcer()
	if err != nil {
		return nil, err
	}
	cfg := &IAM{
		auth: authentication.New(r, authentication.RegisterProvider(password.New())),
		acl:  cas,
	}
	return cfg, nil
}

func WithAuth(auth *authentication.Auth) Options {
	return func(i *IAM) {
		i.auth = auth
	}
}

func WithACL(acl *casbin.Enforcer) Options {
	return func(i *IAM) {
		i.acl = acl
	}
}
