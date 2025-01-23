package server

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/neghi-go/iam"
	"github.com/neghi-go/iam/sessions/store"
)

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

	session *Session
}

func NewServerSession() *Server {
	return &Server{}
}

// Generate implements sessions.Session.
func (s *Server) Generate(w http.ResponseWriter, subject string, params ...interface{}) error {
	//Generate Session
	session := s.generateSession()
	session.data.Set("subject", subject)
	for idx, data := range params {
		session.data.Set(fmt.Sprint(idx), data)
	}
	//Persist session to Store
	d, err := iam.GobEncode(session.data.data)
	if err != nil {
		return err
	}
	err = s.store.Set(session.id, d, s.absoluteTimeout)
	if err != nil {
		return err
	}
	//Send Cookie to
	http.SetCookie(w, &http.Cookie{
		Name:  s.identifier,
		Value: session.id,

		Expires:  time.Now().Add(s.absoluteTimeout * time.Second).UTC(),
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
	d, err := s.store.Get(key)
	if err != nil {
		return err
	}
	err = iam.GobDecode(d, &data)
	if err != nil {
		return err
	}
	s.session = &Session{
		id: key,
		data: &Data{
			mu:   &sync.RWMutex{},
			data: data,
		},
	}
	return nil
}

func (s *Server) generateSession() *Session {
	scs := &Session{
		id: s.keyGenFunc(),
		data: &Data{
			mu:   &sync.RWMutex{},
			data: make(map[string]interface{}),
		},
	}
	return scs
}
