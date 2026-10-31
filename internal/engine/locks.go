package engine

import "sync"

// keyedLocks serializes work per key (a digest) among the workers of a monitoring cycle
// (docs/adr/0026-concurrent-monitoring.md). Entries are dropped when nobody holds or waits for
// them, so the map stays as small as the work in flight.
type keyedLocks struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

type keyedLock struct {
	mu    sync.Mutex
	users int
}

// lock takes the key's lock and returns its release.
func (k *keyedLocks) lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*keyedLock{}
	}
	l, ok := k.locks[key]
	if !ok {
		l = &keyedLock{}
		k.locks[key] = l
	}
	l.users++
	k.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		if l.users--; l.users == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
