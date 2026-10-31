package oci

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

type countingRT struct {
	mu    sync.Mutex
	hosts map[string]int
}

func (c *countingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.hosts[req.URL.Host]++
	c.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: http.NoBody, Request: req}, nil
}

func TestRateLimitSchedule(t *testing.T) {
	now := time.Unix(0, 0)
	r := RateLimit(&countingRT{hosts: map[string]int{}}, 10, 3).(*rateLimited)
	r.now = func() time.Time { return now }
	var waits []time.Duration
	for range 5 {
		waits = append(waits, r.reserve("registry.test"))
	}
	// A burst of 3 goes at once, then one every 100ms.
	want := []time.Duration{0, 0, 0, 100 * time.Millisecond, 200 * time.Millisecond}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits = %v, want %v", waits, want)
		}
	}
	if w := r.reserve("other.test"); w != 0 {
		t.Errorf("another registry has its own budget: %v", w)
	}
	now = now.Add(time.Second)
	if w := r.reserve("registry.test"); w != 0 {
		t.Errorf("an idle second refills the budget: %v", w)
	}
}

func TestRateLimitTransport(t *testing.T) {
	base := &countingRT{hosts: map[string]int{}}
	rt := RateLimit(base, 50, 1) // one request every 20ms
	start := time.Now()
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, "https://registry.test/v2/", nil)
			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	if d := time.Since(start); d < 75*time.Millisecond {
		t.Errorf("5 requests at 50/s took %v", d)
	}
	if base.hosts["registry.test"] != 5 {
		t.Errorf("requests = %v", base.hosts)
	}

	// A request whose context ends while it waits is not sent.
	ctx, cancel := context.WithCancel(context.Background())
	slow := RateLimit(base, 0.1, 1) // 10s between requests
	first, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://slow.test/", nil)
	resp, err := slow.RoundTrip(first)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	cancel()
	second, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://slow.test/", nil)
	resp, err = slow.RoundTrip(second)
	if err == nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, context.Canceled) || base.hosts["slow.test"] != 1 {
		t.Errorf("cancelled wait: %v, sent %d", err, base.hosts["slow.test"])
	}
	if RateLimit(base, 0, 1) != http.RoundTripper(base) {
		t.Error("rps 0 disables the limit")
	}
}
