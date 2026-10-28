// Package notifytest is the conformance kit for notifiers (docs/extending/notifier.md). A
// notifier's test wires the notifier to fake endpoints and calls CheckNotifier; Receiver is a
// fake HTTP endpoint for notifiers that post over HTTP.
package notifytest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/notify"
)

// Fixture is a notifier wired by its test to fake endpoints.
type Fixture struct {
	// Name is the notifier's registered name.
	Name string
	// Notifier sends to an endpoint that accepts every message.
	Notifier notify.Notifier
	// Received returns what that endpoint received so far, one entry per request or mail,
	// without transport credentials (headers): the payloads people see.
	Received func() []string
	// Failing sends to an endpoint that rejects every message and echoes the request,
	// credentials included, in its answer.
	Failing notify.Notifier
	// Hanging sends to an endpoint that never answers.
	Hanging notify.Notifier
	// Redirecting sends to an HTTP endpoint that redirects to another one, and Followed
	// reports whether the other one was reached; nil for notifiers that do not use HTTP.
	Redirecting notify.Notifier
	Followed    func() bool
	// Secret is a credential the notifier was given: no error or payload may contain it.
	Secret string
}

// Injected is the header a hostile event tries to inject; no payload may hold it on a line of
// its own.
const Injected = "X-Injected: 1"

// HostileEvents are events whose text fields carry what scanner output may hold: line breaks
// that try to inject headers, markup, mentions, bidirectional overrides, oversized text.
func HostileEvents() []notify.Event {
	evil := "\r\n" + Injected + "\r\n\r\n<script>alert(1)</script> *bold* _it_ `code` ```\n@here``` [link](https://evil.example) <!channel> @room @everyone \u202egnp.exe"
	first := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	return []notify.Event{
		{Key: "finding_new:1", Kind: notify.FindingNewKEV, Finding: &notify.Finding{
			ID: 1, Lineage: 1, VulnID: "CVE-2024-3094", Title: "xz backdoor" + evil, Severity: "critical", KEV: true,
			CVSS: 10, EPSS: 0.9, Package: "xz-libs" + evil, Version: "5.6.0", PURL: "pkg:rpm/xz-libs@5.6.0",
			Digest: "sha256:aaaa", Targets: []string{"registry.test/app:prod" + evil}, State: "open", FirstDetected: first,
		}},
		{Key: "sla_breached:2:2026-10-31T09:00:00Z", Kind: notify.SLABreached, Finding: &notify.Finding{
			ID: 2, Lineage: 2, VulnID: "CVE-2023-45853", Title: strings.Repeat("long title ", 2000), Severity: "high",
			Package: "zlib", Version: "1.2.13-r0", FixVersions: []string{"1.2.13-r1" + evil}, Digest: "sha256:bbbb",
			State: "triaged", FirstDetected: first, SLADue: first.AddDate(0, 0, 30),
		}},
		{Key: "health:registry_auth:ghcr.io:2026-10-01T09:00:00Z", Kind: notify.HealthOpened, Health: &notify.Health{
			Check: "registry_auth", Subject: "ghcr.io" + evil, Severity: "high", Detail: "401 Unauthorized" + evil, FirstSeen: first,
		}},
	}
}

// CheckNotifier verifies a notifier's contract: registration, one message per event and
// digests delivered with every event, hostile text neutralised, test messages, cancellation,
// timeouts, failures reported without credentials, no redirect followed.
func CheckNotifier(t *testing.T, f Fixture) {
	t.Helper()
	p, ok := notify.LookupNotifier(f.Name)
	if !ok {
		t.Fatalf("notifier %q is not registered", f.Name)
	}
	if p.Description == "" {
		t.Errorf("notifier %q has no description", f.Name)
	}
	for _, opt := range p.Options {
		credential := false
		for _, word := range []string{"token", "password", "secret", "key"} {
			credential = credential || strings.Contains(opt, word)
		}
		if credential && !strings.HasSuffix(opt, "_env") {
			t.Errorf("option %q holds a credential: it must name an environment variable (…_env)", opt)
		}
	}

	ctx := context.Background()
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	events := HostileEvents()
	before := len(f.Received())
	for _, e := range events {
		if err := f.Notifier.Send(ctx, notify.Message{Channel: "kit", Events: []notify.Event{e}, SentAt: now}); err != nil {
			t.Fatalf("send %s: %v", e.Kind, err)
		}
	}
	if err := f.Notifier.Send(ctx, notify.Message{Channel: "kit", Digest: true, Events: events, SentAt: now}); err != nil {
		t.Fatalf("send digest: %v", err)
	}
	if err := f.Notifier.Send(ctx, notify.Message{Channel: "kit", Test: true, SentAt: now}); err != nil {
		t.Fatalf("send test message: %v", err)
	}
	got := f.Received()[before:]
	if len(got) < len(events)+2 {
		t.Fatalf("the endpoint received %d payloads, want at least %d (one per message)", len(got), len(events)+2)
	}
	for i, e := range events {
		id := e.Key
		switch {
		case e.Finding != nil:
			id = e.Finding.VulnID
		case e.Health != nil:
			id = e.Health.Check
		}
		if !strings.Contains(got[i], id) {
			t.Errorf("payload for %s does not mention %s", e.Kind, id)
		}
		if !strings.Contains(got[len(events)], id) {
			t.Errorf("the digest does not mention %s", id)
		}
	}
	for i, payload := range got {
		for line := range strings.Lines(payload) {
			if strings.TrimSpace(line) == Injected {
				t.Errorf("payload %d: hostile text injected a line %q", i, Injected)
			}
		}
		if f.Secret != "" && strings.Contains(payload, f.Secret) {
			t.Errorf("payload %d contains the credential", i)
		}
	}

	msg := notify.Message{Channel: "kit", Events: events[:1], SentAt: now}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.Notifier.Send(cancelled, msg); err == nil {
		t.Error("send must honour context cancellation")
	}
	errs := map[string]error{"failing endpoint": f.Failing.Send(ctx, msg)}
	if f.Hanging != nil {
		short, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		start := time.Now()
		errs["hanging endpoint"] = f.Hanging.Send(short, msg)
		cancel()
		if time.Since(start) > 5*time.Second {
			t.Error("send to a hanging endpoint must stop at the context deadline")
		}
	}
	if f.Redirecting != nil {
		errs["redirect"] = f.Redirecting.Send(ctx, msg)
		if f.Followed() {
			t.Error("the notifier followed a redirect: it would carry its credential or signature elsewhere")
		}
	}
	for what, err := range errs {
		if err == nil {
			t.Errorf("%s: want an error", what)
			continue
		}
		if f.Secret != "" && strings.Contains(err.Error(), f.Secret) {
			t.Errorf("%s: the error contains the credential", what)
		}
	}
}

// Mode is how a Receiver answers.
type Mode int

const (
	// Accept answers 200 to every request.
	Accept Mode = iota
	// Reject answers 401 and echoes the request (URL and headers, credentials included).
	Reject
	// Hang never answers.
	Hang
	// Redirect answers 307 to another receiver, which records whether it was reached.
	Redirect
)

// Receiver is a fake HTTPS endpoint (with a TLS certificate Client trusts) that records the
// bodies it receives.
type Receiver struct {
	URL    string
	Client *http.Client
	srv    *httptest.Server
	mu     sync.Mutex
	bodies []string
	header []http.Header
	reqs   []string
	other  *httptest.Server
	hits   int
}

// NewReceiver starts a receiver answering in mode; it stops at the end of the test.
func NewReceiver(t *testing.T, mode Mode) *Receiver {
	t.Helper()
	r := &Receiver{}
	stop := make(chan struct{})
	if mode == Redirect {
		r.other = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			r.mu.Lock()
			r.hits++
			r.mu.Unlock()
		}))
		t.Cleanup(r.other.Close)
	}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(req.Body, 4<<20))
		r.mu.Lock()
		r.bodies = append(r.bodies, string(body))
		r.header = append(r.header, req.Header.Clone())
		r.reqs = append(r.reqs, req.Method+" "+req.URL.EscapedPath())
		r.mu.Unlock()
		switch mode {
		case Accept:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		case Reject:
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "denied %s %s\n", req.Method, req.URL.String()) //nolint:gosec // G705: the fake echoes the request on purpose, as a hostile endpoint
			for k, v := range req.Header {
				fmt.Fprintf(w, "%s: %s\n", k, strings.Join(v, ","))
			}
		case Hang:
			select {
			case <-req.Context().Done():
			case <-stop:
			}
		case Redirect:
			http.Redirect(w, req, r.other.URL+req.URL.Path, http.StatusTemporaryRedirect) //nolint:gosec // G710: redirects to the fake's own second server
		}
	}))
	t.Cleanup(func() {
		close(stop)
		r.srv.Close()
	})
	r.URL = r.srv.URL
	r.Client = r.srv.Client()
	return r
}

// Bodies returns the bodies received so far.
func (r *Receiver) Bodies() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.bodies...)
}

// Headers returns the headers of the requests received so far.
func (r *Receiver) Headers() []http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]http.Header(nil), r.header...)
}

// Requests returns "METHOD escaped-path" of the requests received so far.
func (r *Receiver) Requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.reqs...)
}

// Followed reports whether a Redirect receiver's target was reached.
func (r *Receiver) Followed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits > 0
}
