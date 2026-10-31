package engine

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestKeyedLocks(t *testing.T) {
	var k keyedLocks
	var inside, maxInside atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := k.lock("sha256:a")
			if n := inside.Add(1); n > maxInside.Load() {
				maxInside.Store(n)
			}
			inside.Add(-1)
			unlock()
		}()
	}
	// Another key is never blocked by the first.
	unlock := k.lock("sha256:b")
	unlock()
	wg.Wait()
	if maxInside.Load() != 1 {
		t.Errorf("%d holders of one key at once", maxInside.Load())
	}
	if len(k.locks) != 0 {
		t.Errorf("entries left after use: %d", len(k.locks))
	}
}
