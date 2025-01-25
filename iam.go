package iam

import (
	"github.com/neghi-go/iam/auth"
)

type Options func(*IAM)

type IAM struct {
	auth *auth.Auth
}

func New(opts ...Options) error {
	cfg := &IAM{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg.auth.Build()
}

func WithAuth(auth *auth.Auth) Options {
	return func(i *IAM) {
		i.auth = auth
	}
}
