package redis

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

var test_url string

func TestMain(m *testing.M) {
	client := testcontainers.ContainerRequest{
		Image:        "redis:alpine",
		ExposedPorts: []string{"6379/tcp"},
	}
	redisClient, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: client,
		Started:          true,
	})
	if err != nil {
		panic(err)
	}

	test_url, _ = redisClient.Endpoint(context.Background(), "")
	exitVal := m.Run()
	_ = redisClient.Terminate(context.Background())
	os.Exit(exitVal)
}

func TestRedisStore(t *testing.T) {
	testKey := "test-key"
	testValue := []byte("hello")
	rc, err := New(WithURL("redis://" + test_url))
	require.NoError(t, err)

	t.Run("Test Set", func(t *testing.T) {
		err := rc.Set(context.Background(), testKey, testValue, time.Second*20)
		require.NoError(t, err)
	})

	t.Run("Test Read", func(t *testing.T) {
		val, err := rc.Get(context.Background(), testKey)
		require.NoError(t, err)
		assert.Equal(t, testValue, val)
	})

	t.Run("Test Del", func(t *testing.T) {
		err := rc.Del(context.Background(), testKey)
		require.NoError(t, err)
	})
}
