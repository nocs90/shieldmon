package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/notify"
	"github.com/nocs90/shieldmon/internal/notify/notifytest"
)

const secret = "s3cr3t-k1t-t0ken-value"

// jsonNotifier is the smallest HTTP notifier: it posts the message as JSON with a bearer
// token, through the shared HTTP helpers. It proves the kit and the helpers.
type jsonNotifier struct {
	url    *url.URL
	token  string
	client *http.Client
}

func (n *jsonNotifier) Send(ctx context.Context, m notify.Message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return notify.Post(ctx, n.client, n.url, "application/json", body, http.Header{"Authorization": {"Bearer " + n.token}})
}

func init() {
	notify.RegisterNotifier(notify.Plugin{
		Name: "test-json", Description: "JSON over HTTPS (tests)", Options: []string{"url", "token_env"},
		New: func(s notify.Spec) (notify.Notifier, error) {
			raw, err := s.Options.String("url", "")
			if err != nil {
				return nil, err
			}
			u, err := notify.ParseURL("url", raw)
			if err != nil {
				return nil, err
			}
			token, err := s.Secret("token_env")
			if err != nil {
				return nil, err
			}
			return &jsonNotifier{url: u, token: token, client: notify.HTTPClient(s)}, nil
		},
	})
}

func channel(t *testing.T, r *notifytest.Receiver, name string, digest bool, events ...string) notify.Channel {
	t.Helper()
	chs, err := notify.NewChannels([]notify.ChannelConfig{{
		Name: name, Notifier: "test-json", Digest: digest, Events: events,
		Options: map[string]any{"url": r.URL + "/hook", "token_env": "KIT_TOKEN"},
	}}, notify.Spec{Transport: r.Client.Transport, Env: func(k string) string {
		if k == "KIT_TOKEN" {
			return secret
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	return chs[0]
}

func TestConformanceKit(t *testing.T) {
	ok := notifytest.NewReceiver(t, notifytest.Accept)
	fail := notifytest.NewReceiver(t, notifytest.Reject)
	hang := notifytest.NewReceiver(t, notifytest.Hang)
	redirect := notifytest.NewReceiver(t, notifytest.Redirect)
	notifytest.CheckNotifier(t, notifytest.Fixture{
		Name:        "test-json",
		Notifier:    channel(t, ok, "ok", false).Sender,
		Received:    ok.Bodies,
		Failing:     channel(t, fail, "fail", false).Sender,
		Hanging:     channel(t, hang, "hang", false).Sender,
		Redirecting: channel(t, redirect, "redirect", false).Sender,
		Followed:    redirect.Followed,
		Secret:      secret,
	})
	if h := ok.Headers(); len(h) == 0 || h[0].Get("Authorization") != "Bearer "+secret {
		t.Error("the credential from the environment variable was not used")
	}
}

func TestNewChannelsValidates(t *testing.T) {
	env := func(string) string { return "x" }
	for what, c := range map[string]notify.ChannelConfig{
		"bad name":          {Name: "Sec Ops", Notifier: "test-json"},
		"unknown notifier":  {Name: "a", Notifier: "pager"},
		"unknown event":     {Name: "a", Notifier: "test-json", Events: []string{"finding_fixed"}},
		"unknown option":    {Name: "a", Notifier: "test-json", Options: map[string]any{"uri": "https://x"}},
		"inline credential": {Name: "a", Notifier: "test-json", Options: map[string]any{"url": "https://x", "token_env": "token=glpat-0123456789abcdefghij"}},
		"plain http":        {Name: "a", Notifier: "test-json", Options: map[string]any{"url": "http://hooks.example.com/x"}},
		"user info":         {Name: "a", Notifier: "test-json", Options: map[string]any{"url": "https://u:p@hooks.example.com/x"}},
	} {
		if _, err := notify.NewChannels([]notify.ChannelConfig{c}, notify.Spec{Env: env}); err == nil {
			t.Errorf("%s: must be refused", what)
		} else if strings.Contains(err.Error(), "glpat-") || strings.Contains(err.Error(), "u:p@") {
			t.Errorf("%s: the error repeats the credential: %v", what, err)
		}
	}
	dup := []notify.ChannelConfig{
		{Name: "a", Notifier: "test-json", Options: map[string]any{"url": "https://x.example"}},
		{Name: "a", Notifier: "test-json", Options: map[string]any{"url": "https://y.example"}},
	}
	if _, err := notify.NewChannels(dup, notify.Spec{Env: env}); err == nil {
		t.Error("duplicate channel names must be refused")
	}
	unset := []notify.ChannelConfig{{Name: "a", Notifier: "test-json", Options: map[string]any{"url": "https://x.example", "token_env": "NOPE"}}}
	if _, err := notify.NewChannels(unset, notify.Spec{Env: func(string) string { return "" }}); err == nil || !strings.Contains(err.Error(), "NOPE is not set") {
		t.Errorf("an unset credential variable must be named: %v", err)
	}
	chs, err := notify.NewChannels([]notify.ChannelConfig{{Name: "local", Notifier: "test-json", Options: map[string]any{"url": "http://127.0.0.1:8080/x"}}}, notify.Spec{Env: env})
	if err != nil || !reflect.DeepEqual(chs[0].Kinds, notify.Kinds) {
		t.Errorf("http to loopback is allowed and a channel without events gets every kind: %v %+v", err, chs)
	}
}

var (
	now   = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	since = now.Add(-24 * time.Hour)
)

func active(id, lineage int64, sev string, kev, carried bool, created, due time.Time) notify.Active {
	return notify.Active{
		Finding: notify.Finding{ID: id, VulnID: "CVE-0", Severity: sev, KEV: kev, Package: "p", Version: "1", State: "open", SLADue: due},
		Lineage: lineage, CreatedAt: created, Carried: carried,
	}
}

func keys(events []notify.Event) []string {
	var out []string
	for _, e := range events {
		out = append(out, string(e.Kind)+" "+e.Key)
	}
	return out
}

func TestCollect(t *testing.T) {
	due := func(d time.Duration) time.Time { return now.Add(d) }
	hf := notify.Health{Check: "registry_auth", Subject: "ghcr.io", Severity: "high", FirstSeen: since}
	in := notify.Input{
		Now: now, Since: since, DueSoon: 7 * 24 * time.Hour,
		Active: []notify.Active{
			active(1, 1, "critical", true, false, now, time.Time{}),                        // new, KEV wins
			active(2, 2, "critical", false, false, now, time.Time{}),                       // new critical
			active(3, 3, "high", false, false, now, time.Time{}),                           // new, not critical: nothing
			active(4, 1, "critical", true, true, now, time.Time{}),                         // carried over: not new
			active(5, 5, "critical", false, false, since.Add(-time.Second), time.Time{}),   // before the window
			active(6, 6, "high", false, false, since.Add(-time.Hour), due(-time.Hour)),     // breached
			active(7, 7, "medium", false, false, since.Add(-time.Hour), due(72*time.Hour)), // due soon
			active(8, 8, "low", false, false, since.Add(-time.Hour), due(30*24*time.Hour)), // not yet
		},
		Health: []notify.Health{hf},
	}
	want := []string{
		"finding_new_kev finding_new:1",
		"finding_new_critical finding_new:2",
		"sla_breached sla_breached:6:2026-10-27T11:00:00Z",
		"sla_due_soon sla_due_soon:7:2026-10-30T12:00:00Z",
		"health_opened health:registry_auth:ghcr.io:2026-10-26T12:00:00Z",
	}
	got := notify.Collect(in)
	if !reflect.DeepEqual(keys(got), want) {
		t.Errorf("events:\n got %q\nwant %q", keys(got), want)
	}
	if again := notify.Collect(in); !reflect.DeepEqual(keys(again), want) {
		t.Error("collecting the same state again must give the same keys")
	}
	if got[0].Finding.Lineage != 1 {
		t.Error("events carry the lineage of their finding")
	}
}

func TestCurrentDropsStaleEventsAndRefreshes(t *testing.T) {
	hf := notify.Health{Check: "db_stale", Subject: "grype", Severity: "high", FirstSeen: since}
	old := notify.Collect(notify.Input{
		Now: now, Since: since,
		Active: []notify.Active{active(1, 1, "critical", false, false, now, now.Add(-time.Hour)), active(2, 2, "critical", false, false, now, time.Time{})},
		Health: []notify.Health{hf},
	})
	// Next cycle: finding 1 continues on a new digest as finding 9 (same lineage), finding 2
	// was fixed, the health finding closed and opened again.
	successor := active(9, 1, "critical", false, true, now, now.Add(-time.Hour))
	successor.Targets = []string{"registry.test/app:prod"}
	reopened := hf
	reopened.FirstSeen = now
	cur := notify.Current(old, notify.Input{Active: []notify.Active{successor}, Health: []notify.Health{reopened}})
	if got := keys(cur); !reflect.DeepEqual(got, []string{"finding_new_critical finding_new:1", "sla_breached sla_breached:1:2026-10-27T11:00:00Z"}) {
		t.Fatalf("current = %q", got)
	}
	if cur[0].Finding.ID != 9 || len(cur[0].Finding.Targets) != 1 {
		t.Errorf("a pending event shows the lineage's current finding: %+v", cur[0].Finding)
	}
}

type recorder struct {
	msgs  []notify.Message
	fails int // fail from this message on (0: never)
	err   error
}

func (r *recorder) Send(_ context.Context, m notify.Message) error {
	r.msgs = append(r.msgs, m)
	if r.fails > 0 && len(r.msgs) >= r.fails {
		return r.err
	}
	return nil
}

func events(n int) []notify.Event {
	var out []notify.Event
	for i := range n {
		out = append(out, notify.Event{
			Key: "health:" + string(rune('a'+i%26)) + strings.Repeat("x", i/26), Kind: notify.HealthOpened,
			Health: &notify.Health{Check: "c", Subject: "s", FirstSeen: now},
		})
	}
	return out
}

func TestDispatch(t *testing.T) {
	ctx := context.Background()
	r := &recorder{}
	sent, err := notify.Dispatch(ctx, notify.Channel{Name: "one", Sender: r}, events(3), now)
	if err != nil || len(sent) != 3 || len(r.msgs) != 3 || r.msgs[0].Digest || len(r.msgs[0].Events) != 1 {
		t.Errorf("without digest: one message per event: %v %d %+v", err, len(sent), r.msgs)
	}

	r = &recorder{}
	sent, err = notify.Dispatch(ctx, notify.Channel{Name: "dig", Digest: true, Sender: r}, events(250), now)
	if err != nil || len(sent) != 250 || len(r.msgs) != 3 || len(r.msgs[0].Events) != notify.MaxEventsPerMessage || !r.msgs[0].Digest {
		t.Errorf("digest: messages of up to %d events: %v %d %d", notify.MaxEventsPerMessage, err, len(sent), len(r.msgs))
	}

	r = &recorder{}
	sent, _ = notify.Dispatch(ctx, notify.Channel{Name: "flood", Sender: r}, events(notify.MaxMessagesPerCycle+10), now)
	if len(sent) != notify.MaxMessagesPerCycle {
		t.Errorf("a cycle sends at most %d messages per channel, sent %d", notify.MaxMessagesPerCycle, len(sent))
	}

	r = &recorder{fails: 2, err: errors.New(`POST hooks.example.com: answered 401; Authorization: Bearer abcdefghijklmnopqrstuvwxyz`)}
	sent, err = notify.Dispatch(ctx, notify.Channel{Name: "broken", Sender: r}, events(5), now)
	if len(sent) != 1 || err == nil || len(r.msgs) != 2 {
		t.Fatalf("dispatch stops at the first failure, keeping what was sent: %d %v", len(sent), err)
	}
	if strings.Contains(err.Error(), "abcdefghijklmnop") || !strings.Contains(err.Error(), "channel broken") {
		t.Errorf("errors are redacted and name the channel: %v", err)
	}
}

func TestMessageText(t *testing.T) {
	ev := notifytest.HostileEvents()
	if s := (notify.Message{Events: ev[:1]}).Subject(); !strings.HasPrefix(s, "ShieldMon: New known exploited vulnerability: CVE-2024-3094 in xz-libs") {
		t.Errorf("subject = %q", s)
	}
	if s := (notify.Message{Digest: true, Events: ev}).Subject(); s != "ShieldMon digest: 1 finding new kev, 1 sla breached, 1 health opened" {
		t.Errorf("digest subject = %q", s)
	}
	if got := notify.Clean("a\r\nb\u202ec"+strings.Repeat("x", 10), 8); got != `a\u000d\u000ab\u202ecxx…` {
		t.Errorf("Clean = %q", got)
	}
	lines := ev[1].Lines()
	if !strings.Contains(strings.Join(lines, "\n"), "Remediation due: 2026-10-31") {
		t.Errorf("SLA events give the deadline: %q", lines)
	}
}
