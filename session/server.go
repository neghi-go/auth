package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/neghi-go/session/store"
	"github.com/neghi-go/utilities"
)

type ServerOptions func(*Server)

func WithStore(store store.Store) ServerOptions {
	return func(s *Server) {
		s.store = store
	}
}

type Server struct {
	store store.Store

	absoluteTimeout time.Duration
	idleTimeout     time.Duration

	identifier string
	keyGenFunc func() string

	secure   bool
	httpOnly bool
	domain   string
	path     string
	sameSite http.SameSite

	session *ServerSessionModel
}

// DelField implements sessions.Session.
func (s *Server) DelField(key string) error {
	s.session.data.Del(key)
	return nil
}

// GetField implements sessions.Session.
func (s *Server) GetField(key string) interface{} {
	panic("unimplemented")
}

// SetField implements sessions.Session.
func (s *Server) SetField(key string, value interface{}) error {
	panic("unimplemented")
}

func NewServerSession(opts ...ServerOptions) *Server {
	cfg := &Server{
		store: store.NewMemoryStore(),
		keyGenFunc: func() string {
			buf := make([]byte, 16)
			if _, err := rand.Read(buf); err != nil {
				panic(err)
			}
			return hex.EncodeToString(buf)
		},
		identifier:      "sessions-key",
		sameSite:        http.SameSiteLaxMode,
		secure:          false,
		httpOnly:        true,
		idleTimeout:     0,
		absoluteTimeout: time.Hour,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// Generate implements sessions.Session.
func (s *Server) Generate(w http.ResponseWriter, subject string, params ...interface{}) error {
	//Generate Session
	s.generateSession()
	s.session.data.Set("subject", subject)
	for idx, data := range params {
		s.session.data.Set(fmt.Sprint(idx), data)
	}
	err := s.persistToStore(context.Background())
	if err != nil {
		return err
	}
	//Send Cookie to
	http.SetCookie(w, &http.Cookie{
		Name:  s.identifier,
		Value: s.session.id,

		Expires:  time.Now().Add(time.Duration(s.absoluteTimeout.Seconds()) * time.Second).UTC(),
		Secure:   s.secure,
		HttpOnly: s.httpOnly,

		Domain: s.domain,
		Path:   s.path,

		SameSite: s.sameSite,
	})

	return nil
}

// Validate implements sessions.Session.
func (s *Server) Validate(key string) error {
	data := make(map[string]interface{})
	d, err := s.store.Get(context.Background(), key)
	if err != nil {
		return err
	}
	err = utilities.GobDecode(d, &data)
	if err != nil {
		return err
	}
	s.session = &ServerSessionModel{
		id: key,
		data: &Data{
			mu:   &sync.RWMutex{},
			data: data,
		},
	}
	return nil
}

var _ Session = (*Server)(nil)

func (s *Server) generateSession() {
	scs := &ServerSessionModel{
		id: s.keyGenFunc(),
		data: &Data{
			mu:   &sync.RWMutex{},
			data: map[string]interface{}{},
		},
	}
	s.session = scs
}

func (s *Server) persistToStore(ctx context.Context) error {
	//Persist session to Store
	d, err := utilities.GobEncode(s.session.data.data)
	if err != nil {
		return err
	}
	err = s.store.Set(ctx, s.session.id, d, s.absoluteTimeout)
	if err != nil {
		return err
	}
	return nil
}
