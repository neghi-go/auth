package authorization

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRegisterPolicy(t *testing.T) {
	t.Run("Test JSON File", func(t *testing.T) {
		cfg := NewPDP(WithPath("./test.json"))
		require.NotEmpty(t, cfg)
		t.Log(*cfg.p[0])
	})
	t.Run("Test Yaml File", func(t *testing.T) {
		cfg := NewPDP(WithPath("./test.yaml"))
		require.NotEmpty(t, cfg)
	})
	t.Run("Test YML File", func(t *testing.T) {
		cfg := NewPDP(WithPath("./test.yml"))
		require.NotEmpty(t, cfg)
	})
}

func TestEnforcePolicy(t *testing.T) {
	cfg := NewPDP(WithPath("./test.yml"))
	t.Run("Permit", func(t *testing.T) {
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
		e := cfg.Enforce(attr)
		require.Equal(t, Permit, e)
	})
	t.Run("Deny", func(t *testing.T) {
		attr := Attributes{
			Subject: Subject{
				UserID: uuid.MustParse("b0c75740-6103-4fe6-b4fa-b880559efe5f"),
				Role:   "user",
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
		e := cfg.Enforce(attr)
		require.Equal(t, Deny, e)
	})
	t.Run("No Match", func(t *testing.T) {
		attr := Attributes{
			Subject: Subject{
				UserID: uuid.MustParse("b0c75740-6103-4fe6-b4fa-b880559efe5f"),
				Role:   "user",
			},
			Resource: Resource{
				ID:      uuid.MustParse("b0c75740-6103-4fe6-b4fa-b880559efe5f"),
				OwnerID: uuid.MustParse("b0c75740-6103-4fe6-b4fa-b880559efe5f"),
				URL:     "/resource",
				Method:  MethodDelete,
			},
			Environment: Environment{
				IPAddress:     "10.10.1.1",
				TimeOfRequest: time.Now(),
				Device:        "Iphone",
			},
		}
		e := cfg.Enforce(attr)
		require.Equal(t, Deny, e)
	})
}
