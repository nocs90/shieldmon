package oci

import (
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// RegistryRateLimit is the transport of the monitoring cycle for limits.registry_rps:
// bursts of as many requests as one second allows.
func RegistryRateLimit(rps float64) http.RoundTripper {
	return RateLimit(nil, rps, int(math.Ceil(rps)))
}

// RateLimit returns a transport over base that starts at most rps requests per second to
// each registry host, with bursts of up to burst (docs/adr/0026-concurrent-monitoring.md).
// A request waiting for its turn gives up when its context ends. rps <= 0 returns base; a
// nil base is go-containerregistry's default transport.
func RateLimit(base http.RoundTripper, rps float64, burst int) http.RoundTripper {
	if rps <= 0 {
		return base
	}
	if base == nil {
		base = remote.DefaultTransport
	}
	if burst < 1 {
		burst = 1
	}
	return &rateLimited{
		base: base, interval: time.Duration(float64(time.Second) / rps), burst: burst,
		tat: map[string]time.Time{}, now: time.Now,
	}
}

type rateLimited struct {
	base     http.RoundTripper
	interval time.Duration
	burst    int
	now      func() time.Time

	mu  sync.Mutex
	tat map[string]time.Time // theoretical arrival time of the next request, per host
}

func (r *rateLimited) RoundTrip(req *http.Request) (*http.Response, error) {
	if wait := r.reserve(req.URL.Host); wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-req.Context().Done():
			t.Stop()
			return nil, req.Context().Err()
		}
	}
	return r.base.RoundTrip(req)
}

// reserve books the host's next slot (virtual scheduling: a request may run burst-1
// intervals early) and returns how long to wait for it.
func (r *rateLimited) reserve(host string) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	tat := r.tat[host]
	if tat.Before(now) {
		tat = now
	}
	wait := tat.Sub(now) - time.Duration(r.burst-1)*r.interval
	r.tat[host] = tat.Add(r.interval)
	if wait < 0 {
		return 0
	}
	return wait
}
