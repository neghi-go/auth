package models

import "github.com/google/uuid"

type OauthModel struct {
	ID           uuid.UUID `json:"id" db:"id,index,required,unique"`
	UserID       uuid.UUID `json:"user_id" db:"user_id,index"`
	Provider     string    `json:"provider" db:"provider"`
	AccessToken  string    `json:"access_token" db:"access_token"`
	RefreshToken string    `json:"refresh_token" db:"refresh_token"`
	ExpiresAt    string    `json:"expires_at" db:"expires_at"`
}
