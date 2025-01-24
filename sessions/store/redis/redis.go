package redis

import (
	"context"
	"time"

	"github.com/neghi-go/iam/sessions/store"
	"github.com/redis/go-redis/v9"
)

type Options func(*Redis)

type Redis struct {
	client *redis.Client

	opts *redis.Options

	prefix string
}

func WithURL(url string) Options {
	opt, err := redis.ParseURL(url)
	if err != nil {
		panic(err)
	}
	return func(r *Redis) {
		r.opts = opt
	}
}

func WithPrefix(prefix string) Options {
	return func(r *Redis) {
		r.prefix = prefix
	}
}

// Del implements store.Store.
func (r *Redis) Del(ctx context.Context, key string) error {
	return r.client.Del(ctx, r.prefix+key).Err()
}

// Get implements store.Store.
func (r *Redis) Get(ctx context.Context, key string) ([]byte, error) {
	result, err := r.client.Get(ctx, r.prefix+key).Result()
	if err != nil {
		return nil, err
	}

	return []byte(result), nil
}

// Set implements store.Store.
func (r *Redis) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return r.client.Set(ctx, r.prefix+key, value, ttl).Err()
}

func New(opts ...Options) (*Redis, error) {
	cfg := &Redis{
		prefix: "sessions:",
	}

	for _, opt := range opts {
		opt(cfg)
	}

	cfg.client = redis.NewClient(cfg.opts)

	if err := cfg.client.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}

	return cfg, nil
}

var _ store.Store = (*Redis)(nil)
