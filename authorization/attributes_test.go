package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttributes(t *testing.T) {
	t.Run("Test Read JSON", func(t *testing.T) {
		attr, err := New(WithPath("test.json"))
		assert.NoError(t, err)
		assert.NotEmpty(t, attr)
		t.Log(attr)
	})
	t.Run("Test Read YAML", func(t *testing.T) {
		attr, err := New(WithPath("test.yaml"))
		assert.NoError(t, err)
		assert.NotEmpty(t, attr)
		t.Log(attr)
	})
	t.Run("Test Read YML", func(t *testing.T) {
		attr, err := New(WithPath("test.yml"))
		assert.NoError(t, err)
		assert.NotEmpty(t, attr)
		t.Log(attr)
	})
}
