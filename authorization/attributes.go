package authorization

import (
	"time"

	"github.com/google/uuid"
)

type Action int

const (
	ActionAll Action = iota
	ActionRead
	ActionWrite
	ActionUpdate
	ActionDelete
)

type Method int

const (
	MethodAll Method = iota
	MethodGet
	MethodPost
	MethodDelete
	MethodPatch
	MethodPut
)

type Subject struct {
	UserID uuid.UUID
	Role   string
}

type Resource struct {
	ID      uuid.UUID
	OwnerID uuid.UUID
	URL     string
	Method  Method
}

type Environment struct {
	IPAddress     string
	TimeOfRequest time.Time
	Device        string
}

type Attributes struct {
	Subject     Subject
	Action      []Action
	Resource    Resource
	Environment Environment
}
