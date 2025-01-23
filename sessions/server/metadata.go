package sessions

import "sync"

type Data map[string]interface{}

type metadata struct {
	data Data
	sync.RWMutex
}

func (d *metadata) Get(key string) interface{} {
	d.RLock()
	defer d.RUnlock()
	return d.data[key]
}

func (d *metadata) Set(key string, val interface{}) {
	d.Lock()
	d.data[key] = val
	d.Unlock()
}

func (d *metadata) Del(key string) {
	d.Lock()
	delete(d.data, key)
	d.Unlock()
}

func (d Data) Reset() {
	d = make(Data)
}
