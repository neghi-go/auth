package sessions

import (
	"time"

	"github.com/neghi-go/iam/sessions/server/cookies"
)

type Options func(*SessionManagement)

type SessionManagement struct {
	key             string
	keyGenFunc      func() string
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	cookie          cookies.Cookie
}

func New(opts ...Options) *SessionManagement {
	cfg := &SessionManagement{}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

type SessionModel struct {
	ID       string `json:"id" db:"id"`
	Metadata Data   `json:"metadata" db:"metadata"`
}

type Session struct {
	id     string
	data   *metadata
	config *SessionManagement
}
