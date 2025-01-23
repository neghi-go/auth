package server

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/neghi-go/iam/sessions"
	"github.com/neghi-go/iam/sessions/store"
	"github.com/neghi-go/iam/utils"
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

// DelField implements sessions.Session.
func (s *Server) DelField(key string) error {
	panic("unimplemented")
}

// GetField implements sessions.Session.
func (s *Server) GetField(key string) interface{} {
	panic("unimplemented")
}

// SetField implements sessions.Session.
func (s *Server) SetField(key string, value interface{}) error {
	panic("unimplemented")
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
	d, err := utils.GobEncode(session.data.data)
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
	err = utils.GobDecode(d, &data)
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

var _ sessions.Session = (*Server)(nil)

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
