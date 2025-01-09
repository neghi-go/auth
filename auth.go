package auth

type Auth[T any] struct {
	Providers []AuthProvider
}

func New[T any]() *Auth[T] {
	return &Auth[T]{}
}

