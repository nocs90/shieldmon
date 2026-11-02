package server

import (
	"testing"
	"time"
)

func TestThrottle(t *testing.T) {
	var th throttle
	t0 := time.Date(2026, 11, 2, 20, 0, 0, 0, time.UTC)
	if n, ok := th.allow(t0); !ok || n != 0 {
		t.Fatalf("first event: %d %v", n, ok)
	}
	for i := range 5 {
		if _, ok := th.allow(t0.Add(time.Duration(i+1) * 100 * time.Millisecond)); ok {
			t.Fatalf("event %d within a second let through", i)
		}
	}
	if n, ok := th.allow(t0.Add(time.Second)); !ok || n != 5 {
		t.Errorf("after a second: %d held back, %v", n, ok)
	}
}
