package mongodb

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
		Image:        "mongo:8.0",
		ExposedPorts: []string{"27017/tcp"},
	}

	mongoClient, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: client,
		Started:          true,
	})
	if err != nil {
		panic(err)
	}

	test_url, _ = mongoClient.Endpoint(context.Background(), "")

	exitVal := m.Run()
	_ = mongoClient.Terminate(context.Background())
	os.Exit(exitVal)
}

func TestMongoStore(t *testing.T) {
	testkey := "test-key"
	testVal := []byte("test-value")
	ms, err := New(WithURL("mongodb://"+test_url), WithTTL(time.Second*5))
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
}
