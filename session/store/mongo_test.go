package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

func TestMongoStore(t *testing.T) {
	client := testcontainers.ContainerRequest{
		Image:        "mongo:8.0",
		ExposedPorts: []string{"27017/tcp"},
	}

	mongoClient, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: client,
		Started:          true,
	})
	require.NoError(t, err)

	test_url, _ := mongoClient.Endpoint(context.Background(), "")

	testkey := "test-key"
	testVal := []byte("test-value")
	ms, err := NewMongoDBStore(WithMongoURL("mongodb://"+test_url), WithTTL(time.Second*5))
	require.NoError(t, err)

	t.Run("Test Normal Read/Write/Delete", func(t *testing.T) {
		t.Run("Test Create", func(t *testing.T) {
			err := ms.Set(context.Background(), testkey, testVal, time.Second*10)
			assert.NoError(t, err)
		})

		t.Run("Test Read", func(t *testing.T) {
			val, err := ms.Get(context.Background(), testkey)
			assert.NoError(t, err)
			assert.Equal(t, testVal, val)
		})
		t.Run("Test Delete", func(t *testing.T) {
			err := ms.Del(context.Background(), testkey)
			assert.NoError(t, err)
		})
	})

	err = mongoClient.Terminate(context.Background())
	require.NoError(t, err)
}
