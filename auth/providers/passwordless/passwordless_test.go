package passwordless

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/database/mongodb"
	"github.com/neghi-go/iam/auth/providers"
	"github.com/neghi-go/iam/internal/models"
	"github.com/neghi-go/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

var mongo_url string

func TestMain(m *testing.M) {
	client := testcontainers.ContainerRequest{
		Image:        "mongo:8.0",
		ExposedPorts: []string{"27017/tcp"},
	}
	mongoclient, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
		ContainerRequest: client,
		Started:          true,
	})
	if err != nil {
		panic(err)
	}

	mongo_url, _ = mongoclient.Endpoint(context.Background(), "")
	exitVal := m.Run()
	_ = testcontainers.TerminateContainer(mongoclient)
	os.Exit(exitVal)
}

func TestPasswordless(t *testing.T) {
	var auth_token string
	router := chi.NewRouter()
	mgd, err := mongodb.New("mongodb://"+mongo_url, "test-db")
	if err != nil {
		t.Error(err)
	}
	userModel, err := mongodb.RegisterModel(mgd, "users", models.User{})
	if err != nil {
		t.Error(err)
	}

	j := session.NewJWTSession()

	PasswordlessProvider(WithNotifier(func(email, token string) error {
		auth_token = token
		return nil
	})).Init(router, &providers.ProviderConfig{
		Session: j,
		User:    userModel,
	})

	t.Run("Test Authentication Flow", func(t *testing.T) {

		t.Run("Test Default Action", func(t *testing.T) {
			var buf bytes.Buffer
			body := map[string]string{
				"email": "jon@doe.com",
			}
			err := json.NewEncoder(&buf).Encode(body)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/authorize", &buf)
			res := httptest.NewRecorder()

			router.ServeHTTP(res, req)

			assert.Equal(t, http.StatusOK, res.Code)
		})
		t.Run("Test Resend Action", func(t *testing.T) {
			var buf bytes.Buffer
			body := map[string]string{
				"email": "jon@doe.com",
			}
			if err := json.NewEncoder(&buf).Encode(body); err != nil {
				t.Error(err)
			}

			req := httptest.NewRequest(http.MethodPost, "/authorize?action=resend", &buf)
			res := httptest.NewRecorder()

			router.ServeHTTP(res, req)

			assert.Equal(t, http.StatusOK, res.Code)
			t.Log(res.Body.String())
		})
		t.Run("Test Authenticate Action", func(t *testing.T) {
			var buf bytes.Buffer
			body := map[string]string{
				"email": "jon@doe.com",
				"token": auth_token,
			}
			if err := json.NewEncoder(&buf).Encode(body); err != nil {
				t.Error(err)
			}

			req := httptest.NewRequest(http.MethodPost, "/authorize?action=authenticate", &buf)
			res := httptest.NewRecorder()

			router.ServeHTTP(res, req)

			assert.Equal(t, http.StatusOK, res.Code)
		})
	})
}
