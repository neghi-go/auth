package session

import "sync"

type Data struct {
	mu   *sync.RWMutex
	data map[string]interface{}
}

func (d *Data) Get(key string) interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.data[key]
}

func (d *Data) Set(key string, value interface{}) {
	d.mu.Lock()
	d.data[key] = value
	d.mu.Unlock()
}

func (d *Data) Del(key string) {
	d.mu.RLock()
	delete(d.data, key)
	d.mu.RUnlock()
}

func (d *Data) Reset(key string) {
	d.data = make(map[string]interface{}, 0)
}

type ServerSessionModel struct {
	id   string
	data *Data
}
