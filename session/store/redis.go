package store

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisOptions func(*Redis)

type Redis struct {
	client *redis.Client

	opts *redis.Options

	prefix string
}

func WithRedisURL(url string) RedisOptions {
	opt, err := redis.ParseURL(url)
	if err != nil {
		panic(err)
	}
	return func(r *Redis) {
		r.opts = opt
	}
}

func WithPrefix(prefix string) RedisOptions {
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

func NewRedisStore(opts ...RedisOptions) (*Redis, error) {
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

var _ Store = (*Redis)(nil)
