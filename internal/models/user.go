package models

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID uuid.UUID `json:"id" db:"id,index,required"`

	Email                     string    `json:"email" db:"email,index,required"`
	EmailVerified             bool      `json:"email_verified" db:"email_verified"`
	EmailVerifyToken          string    `json:"-" db:"email_verify_token"`
	EmailVerifyTokenExpiresAt time.Time `json:"-" db:"email_verify_token_expires_at"`

	Password                     string    `json:"-" db:"password"`
	PasswordSalt                 string    `json:"-" db:"password_salt"`
	PasswordResetToken           string    `json:"-" db:"password_reset_token"`
	PasswordVerifyTokenExpiresAt time.Time `json:"-" db:"password_reset_token_expires"`


	LastLogin int64 `json:"last_login" db:"last_login,required"`
}
