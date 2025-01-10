package storage

import "context"

type Store interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, value []byte) error
	Delete(ctx context.Context, key string) error
}
