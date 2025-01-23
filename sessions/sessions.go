package sessions

import "net/http"

type Session interface {
	Generate(w http.ResponseWriter, subject string, params ...interface{}) error
	Validate(key string) error
	GetField(key string) interface{}
	SetField(key string, value interface{}) error
	DelField(key string) error
}
