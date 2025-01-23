package authorization

import (
	"time"

	"github.com/google/uuid"
)

type Method string

const (
	MethodGet    Method = "GET"
	MethodPost   Method = "POST"
	MethodDelete Method = "DELETE"
	MethodPatch  Method = "PATCH"
	MethodPut    Method = "PUT"
)

type Subject struct {
	UserID uuid.UUID `attr:"id"`
	Role   string    `attr:"role"`
}

type Resource struct {
	ID      uuid.UUID `attr:"id"`
	OwnerID uuid.UUID `attr:"owner_id"`
	URL     string    `attr:"url"`
	Method  Method    `attr:"method"`
}

type Environment struct {
	IPAddress     string    `attr:"ip_address"`
	TimeOfRequest time.Time `attr:"time_of_request"`
	Device        string    `attr:"device"`
}

type Attributes struct {
	Subject     Subject     `attr:"subject"`
	Resource    Resource    `attr:"resource"`
	Environment Environment `attr:"environment"`
}
