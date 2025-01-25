package passwordless

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/database"
	"github.com/neghi-go/iam/auth/sessions"
	"github.com/neghi-go/iam/auth/strategy"
	"github.com/neghi-go/iam/models"
	"github.com/neghi-go/iam/utils"
	"github.com/neghi-go/utilities"
)

type Action string

const (
	authenticate Action = "authenticate"
	resend       Action = "resend"
)

type authenticateRequest struct {
	Email string `json:"email"`
}

type Option func(*passwordlessProviderConfig)

type passwordlessProviderConfig struct {
	store  database.Model[models.User]
	notify func(email string, token string) error
}

func WithStore(model database.Model[models.User]) Option {
	return func(ppc *passwordlessProviderConfig) {
		ppc.store = model
	}
}

func WithNotifier(notifier func(email, token string) error) Option {
	return func(ppc *passwordlessProviderConfig) {
		ppc.notify = notifier
	}
}

func New(opts ...Option) *strategy.Provider {
	cfg := &passwordlessProviderConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return &strategy.Provider{
		Type: "magic-link",
		Init: func(r chi.Router, session sessions.Session) {
			r.Post("/authorize", authorize(cfg, session))
		},
	}
}

func authorize(cfg *passwordlessProviderConfig, session sessions.Session) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body authenticateRequest
		res := utilities.JSON(w)
		action := r.URL.Query().Get("action")
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			res.SetStatus(utilities.ResponseError).
				SetStatusCode(http.StatusInternalServerError).
				Send()
			return
		}

		switch Action(action) {
		case authenticate:
			token := r.URL.Query().Get("token")

			if token == "" {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					Send()
				return
			}
			//when url contains token
			//parse token
			tokenValues, _ := utils.Decrypt(token)
			//validate parsed token
			if tokenValues["email"] != body.Email {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					Send()
				return
			}
			timestamp, _ := tokenValues["expiry"].(int64)
			if time.Now().UTC().Unix() > timestamp {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					SetMessage("validation token has expire, please try again").
					Send()
				return
			}

			user, err := cfg.store.WithContext(r.Context()).
				Query(database.WithFilter("email", body.Email)).First()
			if err != nil {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					SetMessage("user not found").
					Send()
				return
			}
			user.LastLogin = time.Now().UTC().Unix()
			if !user.EmailVerified {
				user.EmailVerified = true
			}
			// create session for user
			//create session, either JWT or Cookie and send to user
			err = session.Generate(w, user.ID.String(), user.Email)
			if err != nil {
				utilities.JSON(w).
					SetStatus(utilities.ResponseFail).
					SetStatusCode(http.StatusBadRequest).
					SetMessage(err.Error()).
					Send()
				return
			}

			//update user
			if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", body.Email)).
				Update(*user); err != nil {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					SetMessage("user not updated").
					Send()
				return

			}
			res.SetStatus(utilities.ResponseSuccess).
				SetStatusCode(http.StatusOK).
				SetData(user).
				Send()
		case resend:
			if _, err := cfg.store.WithContext(r.Context()).
				Query(database.WithFilter("email", body.Email)).First(); err != nil {
				res.SetStatus(utilities.ResponseError).
					SetStatusCode(http.StatusBadRequest).
					SetMessage("user not found").
					Send()
				return
			}
			tokenValues := map[string]any{
				"email":  body.Email,
				"expiry": time.Now().Add(time.Minute * 10).UTC().Unix(),
			}
			token, _ := utils.Encrypt(tokenValues)
			// send to user
			_ = cfg.notify(body.Email, token)
			res.SetStatus(utilities.ResponseSuccess).
				SetStatusCode(http.StatusOK).
				Send()
		default:
			//get user if it exist and generate session
			if _, err := cfg.store.WithContext(r.Context()).
				Query(database.WithFilter("email", body.Email)).First(); err != nil {
				user, err := models.NewUser().SetEmail(body.Email).Build()
				if err != nil {
					res.SetStatus(utilities.ResponseError).
						SetStatusCode(http.StatusBadRequest).
						Send()
				}
				if err := cfg.store.WithContext(r.Context()).Save(*user); err != nil {
					res.SetStatus(utilities.ResponseError).
						SetStatusCode(http.StatusBadRequest).
						Send()
					return
				}
			}
			tokenValues := map[string]any{
				"email":  body.Email,
				"expiry": time.Now().Add(time.Minute * 10).UTC().Unix(),
			}
			token, _ := utils.Encrypt(tokenValues)
			_ = cfg.notify(body.Email, token)

			res.SetStatus(utilities.ResponseSuccess).
				SetStatusCode(http.StatusOK).
				SetMessage("please check your email for authentication link").
				Send()
		}

	}
}
