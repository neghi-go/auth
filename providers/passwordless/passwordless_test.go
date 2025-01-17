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
	"github.com/neghi-go/auth/jwt"
	"github.com/neghi-go/auth/models"
	"github.com/neghi-go/database/mongodb"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
)

var mongo_url string

var (
	privKey = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb1FJQkFBS0NBUUI4K3IvSGlmRjZzWGZvdlBtUjNxVWxHVE80TWEvcjllN2xXU3R6MFZpdE80NXI2bHlpCklUZnM5U1JpMUlBUUtTK2JPMnRWTWE1RVJqanVSa3MwSVpaMTNkNTRvRVNSWFd1ZzlwYmxRZ2lDU2VtY0RnRlgKdTNaSWRoSWs5RGJvQnJmOERlbHROdkhQRGMzNVkyMzVqVDRWNW9IaUtYbmovQ1NXakNMQUJIOUZpeWZoNjRObAp6RkxEaTk5djVjdUtCY2JmSHIzMHRGNktRdk1NckNJTFF6eFZUTkpjckxuSmRPMXdkVXhkKzRBSnloZlE3aE5lCldsaHUxVERBd3ZVd0VMc0hxaGhML3ZLYitIdUwwbnQ3b0xVZ0Y4aEFJOENVMHIzVmtjUmZCTkR6d3pvajJqWG0KZkZESHNRQnlGNmQzNFVJWnJCR0grMUNiNHZTYW1uUDdxbjc3QWdNQkFBRUNnZ0VBUzdYRytjVHB3UzdDK2YySQpua0ltL3R0T2huV3JJYUVoTUZTZFN4TDF5ak42Nm9yVnhPMmtxR28wdVo0TFdqN285UHZBNEtJdzlIRXB5Y1pSCmhtb1djSjZRUjdpbThQeUwxNzJwMllYd0M2VmszRUZydE03K0w1VS9GcDNPcVM1d3hFTlZOZkVEK1M5ZXFJWUEKT0IzRkQ1Vk05MG15NmxaemY3T3kxV21rQStjVmRDZmlic20rL0lvYyswUlNKRDk2ZzNHaFNDV0t1WllVcUJKMAp0QXVHemZLTlJJZFBySmwrVHBrc0FFbndhRDFoZkg0NEJITTRKV0Fvb1JVK2l4aGlINWQ3Z1pYbmJ4MkdOazFxCnlkY3NIZGxuRXI5dG9WMjRxQW5ZKzlxQUtCY0hlQ0c1UXlZSFRTOWJJWDdDUTFZbHVkYlBDMGEzUENzdDBhTnUKTUdnaFdRS0JnUURWKzgwUmlOTHJFQ2lXV0d6OWw3bmtHR1JPUnRXZG1KdThCTHpXUjhGdkM1NnJLVGxEZ3M3UwpOME9ybmZPUHNJYkxPaXpIZmdjZVJQcnVKRWE0azd4L3B6OGxOOWpSVXpWeE9EUWwwekt3VkxycFFCdkdHV3FJCk5RMld0ZVNHY1lTejl2TlBYVEpBVFpMclE5a2tpWVdDQzJWaEMyVk11WlVTTGJIRFE2Y1Ivd0tCZ1FDVmhRYTAKaFRUbHl4OStBbll5WDU4bGhBSUFDVmJJQkUxNVNxM3BvMkZ3ZWM2dTAxRkpCZWhvUjJCMnV3MnF0UHZEdlZMYQowblcvUE5QaUJhbW5ZbHcwK3V6Mnhla0lmMG5Dcm9wZTBiUjNNUmU2UURoQ2wvYkExUktGc1lNYWE3VGlPUENECkkxcXlwRFVGL1Zrak81UlRpZ0hYdkg3amZTNU94cFVjSHY3YkJRS0JnSFZYL3kzbGJWeXdZTUdKdmtNV3lEN1kKVFhGTGtPczZlL1NRV0luZGthcjJvVTFWYnV5aHVBODVkU2VRbDdjdFk4M2dtaHZQOWRGWW5JNnBZQXJxSVUyVApocUkvVE93RmlHSU5Jek8yN0s0YjJOLytZdnl3aFdZcVNjaGkrTzN0Skl1WUdmZGtzU0RvS1hCUXBheE9xZU1WCm9zT2oveW9pL3llWDNVcXFOOTA3QW9HQWRmY0FOVWlyVldtT3JTSlFFcW95cTZ5Y3oxNk80enZSekJKSlovNEoKRUc1cHpMRFlmdDUwWUdHQUQrekFlYUJVeWpnQ3VMWTNRK3cvMXlGVW1zVVZybzhTaWhmWEpXY1gwTXRZVERyegpRTjZ3czdlYks1OHRoVElXYlBpQ1VVUU04RGF3T3lhWGxqM0x2N0FFdGJGNTh2YjlRVEpzZ2hydmdDTlkzVmp2CkJla0NnWUFrUjJiNmZ5Ym5iMnZpbThUT2RPbXVFdy9tb3N6LzMxNjgvM3Zla2dpVmRydTFGVjdlR09UZ3drT28KdmxpVmRLb21TTDJpbTJJdkpZUVNobjU1WEhmM01EUEd6M3oyWEl3NndGbytqQm43Z3pZNlhYZzVRWkxmOWpuTwo2YTBjbTg0aStQMFBzYjA2YW5WY2c1QklXa3Y3MGZpeFY1Rnpwbkx4Zk5aYlphZDZzdz09Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t"
	pubKey  = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklUQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FRNEFNSUlCQ1FLQ0FRQjgrci9IaWZGNnNYZm92UG1SM3FVbApHVE80TWEvcjllN2xXU3R6MFZpdE80NXI2bHlpSVRmczlTUmkxSUFRS1MrYk8ydFZNYTVFUmpqdVJrczBJWloxCjNkNTRvRVNSWFd1ZzlwYmxRZ2lDU2VtY0RnRlh1M1pJZGhJazlEYm9CcmY4RGVsdE52SFBEYzM1WTIzNWpUNFYKNW9IaUtYbmovQ1NXakNMQUJIOUZpeWZoNjRObHpGTERpOTl2NWN1S0JjYmZIcjMwdEY2S1F2TU1yQ0lMUXp4VgpUTkpjckxuSmRPMXdkVXhkKzRBSnloZlE3aE5lV2xodTFUREF3dlV3RUxzSHFoaEwvdktiK0h1TDBudDdvTFVnCkY4aEFJOENVMHIzVmtjUmZCTkR6d3pvajJqWG1mRkRIc1FCeUY2ZDM0VUlackJHSCsxQ2I0dlNhbW5QN3FuNzcKQWdNQkFBRT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
)

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

	j, err := jwt.New(jwt.WithPrivateKey(privKey), jwt.WithPublicKey(pubKey))
	if err != nil {
		t.Error(err)
	}
	New(WithJWT(j), WithStore(userModel), WithNotifier(func(email, token string) error {
		auth_token = token
		return nil
	})).Init(router)

	t.Run("Test Authentication Flow", func(t *testing.T) {

		t.Run("Test Default Action", func(t *testing.T) {
			var buf bytes.Buffer

			body := authenticateRequest{
				Email: "jon@doe.com",
			}
			if err := json.NewEncoder(&buf).Encode(body); err != nil {
				t.Error(err)
			}

			req := httptest.NewRequest(http.MethodPost, "/magic-link/authorize", &buf)
			res := httptest.NewRecorder()

			router.ServeHTTP(res, req)

			assert.Equal(t, http.StatusOK, res.Code)
		})
		t.Run("Test Resend Action", func(t *testing.T) {
			var buf bytes.Buffer

			body := authenticateRequest{
				Email: "jon@doe.com",
			}
			if err := json.NewEncoder(&buf).Encode(body); err != nil {
				t.Error(err)
			}

			req := httptest.NewRequest(http.MethodPost, "/magic-link/authorize?action=resend", &buf)
			res := httptest.NewRecorder()

			router.ServeHTTP(res, req)

			assert.Equal(t, http.StatusOK, res.Code)
			t.Log(res.Body.String())
		})
		t.Run("Test Authenticate Action", func(t *testing.T) {
			var buf bytes.Buffer

			body := authenticateRequest{
				Email: "jon@doe.com",
			}
			if err := json.NewEncoder(&buf).Encode(body); err != nil {
				t.Error(err)
			}

			req := httptest.NewRequest(http.MethodPost, "/magic-link/authorize?action=authenticate&token="+auth_token, &buf)
			res := httptest.NewRecorder()

			router.ServeHTTP(res, req)

			assert.Equal(t, http.StatusOK, res.Code)
		})
	})
}
