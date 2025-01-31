package iam

import (
	"context"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/database/mongodb"
	"github.com/neghi-go/iam/internal/models"
	"github.com/neghi-go/session"
	"github.com/neghi-go/session/store"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

var redis_url string
var mongo_url string

func TestMain(m *testing.M) {
	redisReq := testcontainers.ContainerRequest{
		Image:        "redis:alpine",
		ExposedPorts: []string{"6379/tcp"},
	}
	mongoReq := testcontainers.ContainerRequest{
		Image:        "mongo:8.0",
		ExposedPorts: []string{"27017/tcp"},
	}

	redisClient, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: redisReq,
		Started:          true,
	})
	if err != nil {
		panic(err)
	}
	redis_url, _ = redisClient.Endpoint(context.Background(), "")

	mongoClient, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: mongoReq,
		Started:          true,
	})
	if err != nil {
		panic(err)
	}

	mongo_url, _ = mongoClient.Endpoint(context.Background(), "")

	exitVal := m.Run()

	_ = mongoClient.Terminate(context.Background())
	_ = redisClient.Terminate(context.Background())

	os.Exit(exitVal)
}

func TestIAM(t *testing.T) {
	_ = chi.NewRouter()

	mgd, err := mongodb.New("mongodb://"+mongo_url, "test-db")
	require.NoError(t, err)

	_, err = mongodb.RegisterModel(mgd, "users", models.User{})
	require.NoError(t, err)

	store_redis, err := store.NewRedisStore(store.WithRedisURL("redis://" + redis_url))
	require.NoError(t, err)
	_ = session.NewServerSession(session.WithStore(store_redis))
	t.Run("Test Password Stratetgy", func(t *testing.T) {
		////var buf bytes.Buffer
		////body := map[string]interface{}{
		////	"email":    "jon@doe.com",
		////	"password": "pass1234.",
		////}

		////err := json.NewEncoder(&buf).Encode(body)
		////require.NoError(t, err)

		////req := httptest.NewRequest(http.MethodPost, "/login", &buf)
		////res := httptest.NewRecorder()

		////r.ServeHTTP(res, req)
		////assert.Equal(t, res.Code, http.StatusOK)
	})
}
