package models

import (
	"time"

	"github.com/google/uuid"
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

	MFAStrategy string `json:"-" db:"mfa_strategy"`
	LastLogin   int64  `json:"last_login" db:"last_login,required"`
}
