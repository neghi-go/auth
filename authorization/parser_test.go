package authorization

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestParser(t *testing.T) {
	attr := Attributes{
		Subject: Subject{
			UserID: uuid.MustParse("b0c75740-6103-4fe6-b4fa-b880559efe5f"),
			Role:   "admin",
		},
		Resource: Resource{
			ID:      uuid.MustParse("b0c75740-6103-4fe6-b4fa-b880559efe5f"),
			OwnerID: uuid.MustParse("b0c75740-6103-4fe6-b4fa-b880559efe5f"),
			URL:     "/resource",
			Method:  MethodPost,
		},
		Environment: Environment{
			IPAddress:     "10.10.1.1",
			TimeOfRequest: time.Now(),
			Device:        "Iphone",
		},
	}

	p, err := parse(attr)
	require.NoError(t, err)
	require.NotEmpty(t, p)
	t.Log(p)
}
