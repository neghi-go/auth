package password

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/neghi-go/database"
	"github.com/neghi-go/iam/authentication/strategy"
	"github.com/neghi-go/iam/models"
	"github.com/neghi-go/iam/sessions"
	"github.com/neghi-go/utilities"
	"golang.org/x/crypto/argon2"
)

type Action string

const (
	verify Action = "verify"
	resend Action = "resend"
	reset  Action = "reset"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type resetPasswordRequest struct {
	Email       string `json:"email"`
	Token       string `json:"token"`
	NewPassword string `json:"password"`
}

type verifyEmailRequest struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

type Option func(*passwordProviderConfig)

type passwordProviderConfig struct {
	hash   Hasher
	store  database.Model[models.User]
	notify func(email, token string) error
}

func WithStore(userModel database.Model[models.User]) Option {
	return func(ppc *passwordProviderConfig) {
		ppc.store = userModel
	}
}

func WithNotifier(notify func(email, token string) error) Option {
	return func(ppc *passwordProviderConfig) {
		ppc.notify = notify
	}
}

func New(opts ...Option) *strategy.Provider {
	cfg := &passwordProviderConfig{
		hash: &argonHasher{},
	}

	for _, opt := range opts {
		opt(cfg)
	}
	return &strategy.Provider{
		Type: "password",
		Init: func(r chi.Router, session sessions.Session) {
			r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
				action := r.URL.Query().Get("action")
				var body loginRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseError).
						SetStatusCode(http.StatusInternalServerError).
						SetMessage(err.Error()).
						Send()
					return
				}
				//fetch user
				user, err := cfg.store.WithContext(r.Context()).
					Query(database.WithFilter("email", body.Email)).
					First()
				if err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseFail).
						SetStatusCode(http.StatusBadRequest).
						SetMessage(err.Error()).
						Send()
					return
				}

				//check if user email is verified
				if !user.EmailVerified {
					action = string(verify)
				}

				switch Action(action) {
				case verify:
					user = user.GenerateEmailVerifyToken()
					if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
						Update(*user); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}
					if err := cfg.notify(user.Email, user.EmailVerifyToken); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}
					utilities.JSON(w).
						SetStatus(utilities.ResponseSuccess).
						SetStatusCode(http.StatusOK).
						SetMessage("your email is yet to be verified, please check your email for verification code").
						Send()

				default:
					//validate Password
					if err := cfg.hash.compare(body.Password, user.PasswordSalt, user.Password); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}
					user.LastLogin = time.Now().UTC().Unix()
					if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
						Update(*user); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}
					_ = session.Generate(w, user.ID.String(), user.Email, user.Role)
					utilities.JSON(w).
						SetStatus(utilities.ResponseSuccess).
						SetStatusCode(http.StatusOK).
						SetMessage("successfull login attempt").
						SetData(map[string]interface{}{
							"user": user,
						}).
						Send()
				}

			})
			r.Post("/register", func(w http.ResponseWriter, r *http.Request) {
				var body registerRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseError).
						SetStatusCode(http.StatusInternalServerError).
						SetMessage(err.Error() + "unable to get user details").
						Send()
					return
				}

				//validate user data.
				//store validated user
				user, err := models.NewUser().
					SetEmail(body.Email).
					SetPassword(body.Password).
					GenerateSalt().Build()

				if err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseError).
						SetStatusCode(http.StatusInternalServerError).
						SetMessage(err.Error() + "unable to get user details").
						Send()
					return
				}
				user = user.GenerateEmailVerifyToken()

				//hash passwords
				hashedPassword := cfg.hash.hash(body.Password, user.PasswordSalt)
				user.Password = hashedPassword

				//persist user data
				if err := cfg.store.WithContext(r.Context()).Save(*user); err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseError).
						SetStatusCode(http.StatusInternalServerError).
						SetMessage(err.Error()).
						Send()
					return
				}

				//send notification with token
				if err := cfg.notify(user.Email, user.EmailVerifyToken); err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseFail).
						SetStatusCode(http.StatusBadRequest).
						SetMessage(err.Error()).
						Send()
					return
				}
				utilities.JSON(w).
					SetStatus(utilities.ResponseSuccess).
					SetStatusCode(http.StatusOK).
					SetMessage("your verification code has been resent").
					Send()

			})
			r.Post("/password-reset", func(w http.ResponseWriter, r *http.Request) {
				action := r.URL.Query().Get("action")
				var body resetPasswordRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseError).
						SetStatusCode(http.StatusInternalServerError).
						SetMessage(err.Error()).
						Send()
					return
				}
				user, err := cfg.store.WithContext(r.Context()).
					Query(database.WithFilter("email", body.Email)).First()
				if err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseFail).
						SetStatusCode(http.StatusBadRequest).
						SetMessage(err.Error()).
						Send()
					return
				}

				switch Action(action) {
				case reset:
					user = user.GeneratePasswordResetToken()

					if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
						Update(*user); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}

					if err := cfg.notify(user.Email, user.PasswordResetToken); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}
					utilities.JSON(w).
						SetStatus(utilities.ResponseSuccess).
						SetStatusCode(http.StatusOK).
						SetMessage("your reset code has been sent").
						Send()
				default:
					if body.Token != user.PasswordResetToken {
						user.PasswordResetAttempt += 1
						if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
							Update(*user); err != nil {
							utilities.JSON(w).
								SetStatus(utilities.ResponseFail).
								SetStatusCode(http.StatusBadRequest).
								SetMessage(err.Error()).
								Send()
							return
						}
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage("invalid reset token").
							Send()
						return
					}
					if time.Now().UTC().Unix() > user.PasswordResetTokenExpiresAt.Unix() {
						user.PasswordResetAttempt = 0
						user = user.GeneratePasswordResetToken()
						if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
							Update(*user); err != nil {
							utilities.JSON(w).
								SetStatus(utilities.ResponseFail).
								SetStatusCode(http.StatusBadRequest).
								SetMessage(err.Error()).
								Send()
							return
						}
						if err := cfg.notify(user.Email, user.EmailVerifyToken); err != nil {
							utilities.JSON(w).
								SetStatus(utilities.ResponseFail).
								SetStatusCode(http.StatusBadRequest).
								SetMessage(err.Error()).
								Send()
							return
						}
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage("token is expired, a new one has been sent to your mail").
							Send()
						return
					}

					user.PasswordResetToken = ""
					user.PasswordSalt = utilities.Generate(16)
					user.Password = cfg.hash.hash(body.NewPassword, user.PasswordSalt)
					user.PasswordUpdatedOn = time.Now().UTC()
					user.PasswordResetAttempt = 0
					user.PasswordResetTokenCreatedAt = time.Time{}

					if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
						Update(*user); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}

					utilities.JSON(w).
						SetStatus(utilities.ResponseSuccess).
						SetStatusCode(http.StatusOK).
						SetMessage("password changed, redirect to login").
						Send()
				}
			})
			r.Post("/email-verify", func(w http.ResponseWriter, r *http.Request) {
				action := r.URL.Query().Get("action")
				var body verifyEmailRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseError).
						SetStatusCode(http.StatusInternalServerError).
						SetMessage(err.Error()).
						Send()
					return
				}

				user, err := cfg.store.WithContext(r.Context()).
					Query(database.WithFilter("email", body.Email)).
					First()
				if err != nil {
					utilities.JSON(w).
						SetStatus(utilities.ResponseFail).
						SetStatusCode(http.StatusBadRequest).
						SetMessage(err.Error()).
						Send()
					return
				}
				switch Action(action) {
				case resend:
					user = user.GenerateEmailVerifyToken()
					if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
						Update(*user); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}
					if err := cfg.notify(user.Email, user.EmailVerifyToken); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}
					utilities.JSON(w).
						SetStatus(utilities.ResponseSuccess).
						SetStatusCode(http.StatusOK).
						SetMessage("your verification code has been resent").
						Send()
				default:
					if body.Token != user.EmailVerifyToken {
						user.EmailVerifyAttempt += 1
						if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
							Update(*user); err != nil {
							utilities.JSON(w).
								SetStatus(utilities.ResponseFail).
								SetStatusCode(http.StatusBadRequest).
								SetMessage(err.Error()).
								Send()
							return
						}
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage("invalid verification token").
							Send()
						return
					}
					if time.Now().UTC().Unix() > user.EmailVerifyTokenExpiresAt.Unix() {
						user.EmailVerifyAttempt = 0
						user = user.GenerateEmailVerifyToken()
						if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
							Update(*user); err != nil {
							utilities.JSON(w).
								SetStatus(utilities.ResponseFail).
								SetStatusCode(http.StatusBadRequest).
								SetMessage(err.Error()).
								Send()
							return
						}
						if err := cfg.notify(user.Email, user.EmailVerifyToken); err != nil {
							utilities.JSON(w).
								SetStatus(utilities.ResponseFail).
								SetStatusCode(http.StatusBadRequest).
								SetMessage(err.Error()).
								Send()
							return
						}
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage("token is expired, a new one has been sent to your mail").
							Send()
						return
					}

					user.EmailVerifyToken = ""
					user.EmailVerifyAttempt = 0
					user.EmailVerified = true
					user.EmailVerifyTokenExpiresAt = time.Time{}
					user.EmailVerifyTokenCreatedAt = time.Time{}
					user.EmailVerifiedAt = time.Now().UTC()
					if err := cfg.store.WithContext(r.Context()).Query(database.WithFilter("email", user.Email)).
						Update(*user); err != nil {
						utilities.JSON(w).
							SetStatus(utilities.ResponseFail).
							SetStatusCode(http.StatusBadRequest).
							SetMessage(err.Error()).
							Send()
						return
					}

					utilities.JSON(w).
						SetStatus(utilities.ResponseSuccess).
						SetStatusCode(http.StatusOK).
						SetMessage("email successfully verified, redirect to login").
						Send()
				}
			})
		},
	}
}

type Hasher interface {
	hash(password string, salt string) string
	compare(password, salt, compare string) error
}

type argonHasher struct{}

func (a *argonHasher) hash(password string, salt string) string {
	buf := argon2.IDKey([]byte(password), []byte(salt), 2, 19*1024, 1, 32)
	return base64.RawStdEncoding.EncodeToString(buf)
}
func (a *argonHasher) compare(password, salt, compare string) error {
	pass := a.hash(password, salt)
	if subtle.ConstantTimeCompare([]byte(pass), []byte(compare)) != 1 {
		return errors.New("passwords don't Match")
	}
	return nil
}
