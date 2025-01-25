package password

import (
	"github.com/neghi-go/database"
	"github.com/neghi-go/iam/models"
)

type Option func(*passwordStrategy)

type passwordStrategy struct {
	hash   Hasher
	store  database.Model[models.User]
	notify func(email, token string) error
}

func WithStore(userModel database.Model[models.User]) Option {
	return func(ppc *passwordStrategy) {
		ppc.store = userModel
	}
}

func WithNotifier(notify func(email, token string) error) Option {
	return func(ppc *passwordStrategy) {
		ppc.notify = notify
	}
}
