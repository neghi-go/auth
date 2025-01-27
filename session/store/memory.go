package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

type items struct {
	object []byte
	ttl    time.Time
}

type Memory struct {
	mu    *sync.RWMutex
	items map[string]items
}

func NewMemoryStore() *Memory {
	return &Memory{
		mu:    &sync.RWMutex{},
		items: make(map[string]items, 0),
	}
}

// Del implements store.Store.
func (m *Memory) Del(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
	return nil
}

// Get implements store.Store.
func (m *Memory) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.items[key]
	if !ok {
		return nil, errors.New("item not found")
	}
	if d.ttl.Unix() < time.Now().UTC().Unix() {
		return nil, errors.New("item is expired")
	}
	return d.object, nil
}

// Set implements store.Store.
func (m *Memory) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = items{
		object: value,
		ttl:    time.Now().Add(time.Duration(ttl.Seconds())).UTC(),
	}
	return nil
}

var _ Store = (*Memory)(nil)
