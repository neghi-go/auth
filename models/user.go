package models

import (
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/neghi-go/utilities"
)

var (
	EmailRegex    = regexp.MustCompile(``)
	PasswordRegex = regexp.MustCompile(``)

	ErrInvalidEmail    = errors.New("user: provided email is not valid")
	ErrInvalidPassword = errors.New("user: password is in an invalid format")
)

type User struct {
	ID uuid.UUID `json:"id" db:"id,index,required,unique"`

	Email                     string    `json:"email" db:"email,unique,index,required"`
	EmailVerified             bool      `json:"email_verified" db:"email_verified"`
	EmailVerifiedAt           time.Time `json:"email_verified_at" db:"email_verified_at"`
	EmailVerifyToken          string    `json:"-" db:"email_verify_token"`
	EmailVerifyAttempt        int       `json:"-" db:"email_verify_attempt"`
	EmailVerifyTokenCreatedAt time.Time `json:"-" db:"email_verify_token_created_at"`
	EmailVerifyTokenExpiresAt time.Time `json:"-" db:"email_verify_token_expires_at"`

	Password                    string    `json:"-" db:"password"`
	PasswordSalt                string    `json:"-" db:"password_salt"`
	PasswordResetToken          string    `json:"-" db:"password_reset_token"`
	PasswordResetAttempt        int       `json:"-" db:"password_reset_attempt"`
	PasswordResetTokenCreatedAt time.Time `json:"-" db:"password_reset_token_created_at"`
	PasswordResetTokenExpiresAt time.Time `json:"-" db:"password_reset_token_expires"`
	PasswordUpdatedOn           time.Time `json:"-" db:"password_updated_on"`

	LastLogin int64 `json:"last_login" db:"last_login,required"`
}

func (u *User) GenerateEmailVerifyToken() *User {
	u.EmailVerifyToken = utilities.Generate(4)
	u.EmailVerifyTokenExpiresAt = time.Now().Add(time.Hour).UTC()
	u.EmailVerifyTokenCreatedAt = time.Now().UTC()
	return u
}

func (u *User) GeneratePasswordResetToken() *User {
	u.PasswordResetToken = utilities.Generate(6)
	u.PasswordResetTokenExpiresAt = time.Now().Add(time.Hour).UTC()
	u.PasswordResetTokenCreatedAt = time.Now().UTC()
	return u
}

type UserBuilder struct {
	user *User
}

func NewUser() *UserBuilder {
	return &UserBuilder{
		user: &User{},
	}
}

func (ub *UserBuilder) SetEmail(email string) *UserBuilder {
	ub.user.Email = email
	return ub
}
func (ub *UserBuilder) SetPassword(password string) *UserBuilder {
	ub.user.Password = password
	return ub
}

func (ub *UserBuilder) GenerateSalt() *UserBuilder {
	ub.user.PasswordSalt = utilities.Generate(16)
	return ub
}

func (ub *UserBuilder) Build() (*User, error) {
	ub.user.ID = uuid.New()
	if ok := EmailRegex.MatchString(ub.user.Email); !ok {
		return nil, ErrInvalidEmail
	}

	if ok := PasswordRegex.MatchString(ub.user.Password); !ok {
		return nil, ErrInvalidPassword
	}
	return ub.user, nil
}
