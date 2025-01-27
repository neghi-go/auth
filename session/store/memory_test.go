package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMemoryStore(t *testing.T) {
	testValue := []byte("hello")
	testKey := "test-key"

	m := NewMemoryStore()

	t.Run("Test Save", func(t *testing.T) {
		err := m.Set(context.Background(), testKey, testValue, time.Second*10)
		assert.NoError(t, err)
	})
	t.Run("Test Read", func(t *testing.T) {
		val, err := m.Get(context.Background(), testKey)
		assert.NoError(t, err)
		assert.Equal(t, testValue, val)
	})

	time.Sleep(time.Second * 10)

	t.Run("Test Expired Read", func(t *testing.T) {
		val, err := m.Get(context.Background(), testKey)
		assert.Error(t, err)
		assert.Empty(t, val)
	})

	t.Run("Test Delete", func(t *testing.T) {
		err := m.Del(context.Background(), testKey)
		assert.NoError(t, err)
	})
}
