package authorization

import (
	"testing"

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
