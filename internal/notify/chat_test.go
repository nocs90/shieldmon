package notify_test

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/notify"
	"github.com/nocs90/shieldmon/internal/notify/notifytest"
)

const (
	hookPath    = "/services/T0000000/B0000000/s3cretw3bhookpath0123"
	matrixToken = "syt_c2hpZWxkbW9u_s3cretmatrixtoken_0abc12"
	room        = "!opaqueRoomId:example.org"
)

func chatChannel(t *testing.T, notifier string, r *notifytest.Receiver, opts map[string]any, env map[string]string) (notify.Channel, error) {
	t.Helper()
	chs, err := notify.NewChannels([]notify.ChannelConfig{{Name: "chat", Notifier: notifier, Options: opts}},
		notify.Spec{Transport: r.Client.Transport, Env: func(k string) string { return env[k] }})
	if err != nil {
		return notify.Channel{}, err
	}
	return chs[0], nil
}

// chatFixture wires a notifier to each kind of fake endpoint.
func chatFixture(t *testing.T, notifier, secret string, wire func(r *notifytest.Receiver) (map[string]any, map[string]string)) (notifytest.Fixture, *notifytest.Receiver) {
	t.Helper()
	mk := func(r *notifytest.Receiver) notify.Notifier {
		opts, env := wire(r)
		ch, err := chatChannel(t, notifier, r, opts, env)
		if err != nil {
			t.Fatal(err)
		}
		return ch.Sender
	}
	ok := notifytest.NewReceiver(t, notifytest.Accept)
	redirect := notifytest.NewReceiver(t, notifytest.Redirect)
	return notifytest.Fixture{
		Name:        notifier,
		Notifier:    mk(ok),
		Received:    ok.Bodies,
		Failing:     mk(notifytest.NewReceiver(t, notifytest.Reject)),
		Hanging:     mk(notifytest.NewReceiver(t, notifytest.Hang)),
		Redirecting: mk(redirect),
		Followed:    redirect.Followed,
		Secret:      secret,
	}, ok
}

func webhookWiring(r *notifytest.Receiver) (map[string]any, map[string]string) {
	return map[string]any{"webhook_url_env": "CHAT_HOOK"}, map[string]string{"CHAT_HOOK": r.URL + hookPath}
}

func matrixWiring(r *notifytest.Receiver) (map[string]any, map[string]string) {
	return map[string]any{"homeserver": r.URL + "/matrix", "room": room, "token_env": "MATRIX_TOKEN"}, map[string]string{"MATRIX_TOKEN": matrixToken}
}

func texts(t *testing.T, bodies []string, field string) []string {
	t.Helper()
	var out []string
	for _, b := range bodies {
		var m map[string]any
		if err := json.Unmarshal([]byte(b), &m); err != nil {
			t.Fatalf("payload is not JSON: %v", err)
		}
		s, _ := m[field].(string)
		out = append(out, s)
	}
	return out
}

func TestSlackConformance(t *testing.T) {
	f, ok := chatFixture(t, "slack", "s3cretw3bhookpath0123", webhookWiring)
	notifytest.CheckNotifier(t, f)
	for i, text := range texts(t, ok.Bodies(), "text") {
		if strings.Count(text, "```") != 2 {
			t.Errorf("message %d: hostile text must stay inside one code block:\n%s", i, text)
		}
		if strings.ContainsAny(strings.ReplaceAll(text, "&lt;", ""), "<>") {
			t.Errorf("message %d: an unescaped < or > could form a mention or link:\n%s", i, text)
		}
	}
	if text := texts(t, ok.Bodies(), "text")[0]; !strings.Contains(text, "&lt;!channel&gt;") || !strings.HasPrefix(text, "*ShieldMon: New known exploited vulnerability*\n") {
		t.Errorf("slack text:\n%s", text)
	}
}

func TestMattermostConformance(t *testing.T) {
	f, ok := chatFixture(t, "mattermost", "s3cretw3bhookpath0123", webhookWiring)
	notifytest.CheckNotifier(t, f)
	mention := regexp.MustCompile(`@(channel|all|here|everyone|room)`)
	for i, text := range texts(t, ok.Bodies(), "text") {
		head, code, found := strings.Cut(text, "```")
		if !found || strings.Count(text, "```") != 2 || mention.MatchString(head) || !strings.HasSuffix(code, "```") {
			t.Errorf("message %d: mentions and markup only inside one code block:\n%s", i, text)
		}
	}
}

func TestMatrixConformance(t *testing.T) {
	f, ok := chatFixture(t, "matrix", matrixToken, matrixWiring)
	notifytest.CheckNotifier(t, f)
	reqs, heads := ok.Requests(), ok.Headers()
	path := regexp.MustCompile(`^PUT /matrix/_matrix/client/v3/rooms/%21opaqueRoomId:example\.org/send/m\.room\.message/msg_[0-9a-f]{32}$`)
	if !path.MatchString(reqs[0]) {
		t.Errorf("request %q", reqs[0])
	}
	if heads[0].Get("Authorization") != "Bearer "+matrixToken {
		t.Error("the access token goes in the Authorization header")
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(ok.Bodies()[0]), &ev); err != nil {
		t.Fatal(err)
	}
	mentions, isMap := ev["m.mentions"].(map[string]any)
	if ev["msgtype"] != "m.notice" || !isMap || len(mentions) != 0 {
		t.Errorf("an m.notice that mentions nobody: %v", ev)
	}
	if html, _ := ev["formatted_body"].(string); strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;script&gt;") {
		t.Errorf("formatted_body must escape HTML: %s", html)
	}

	// A retry of the same events reuses the transaction ID, which the homeserver deduplicates.
	n := f.Notifier
	m := notify.Message{Channel: "chat", Events: notifytest.HostileEvents()[1:2], SentAt: time.Now()}
	for range 2 {
		if err := n.Send(context.Background(), m); err != nil {
			t.Fatal(err)
		}
	}
	reqs = ok.Requests()
	if reqs[len(reqs)-1] != reqs[len(reqs)-2] {
		t.Errorf("retries must reuse the transaction ID: %q %q", reqs[len(reqs)-2], reqs[len(reqs)-1])
	}
}

func TestChatDigestIsBounded(t *testing.T) {
	r := notifytest.NewReceiver(t, notifytest.Accept)
	ch, err := chatChannel(t, "mattermost", r, map[string]any{"webhook_url_env": "H"}, map[string]string{"H": r.URL + hookPath})
	if err != nil {
		t.Fatal(err)
	}
	var evs []notify.Event
	for i := range notify.MaxEventsPerMessage {
		evs = append(evs, notify.Event{Key: fmt.Sprint(i), Kind: notify.FindingNewCritical, Finding: &notify.Finding{
			VulnID: fmt.Sprintf("CVE-2026-%04d", i), Package: strings.Repeat("p", 5000), Version: "1", Severity: "critical",
		}})
	}
	if err := ch.Sender.Send(context.Background(), notify.Message{Channel: "chat", Digest: true, Events: evs, SentAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	text := texts(t, r.Bodies(), "text")[0]
	if len(text) > 16000 || !strings.Contains(text, "more event(s)") {
		t.Errorf("a digest stays within Mattermost's post size and says what it leaves out (%d bytes)", len(text))
	}
}

func TestChatRefusesWeakConfiguration(t *testing.T) {
	r := notifytest.NewReceiver(t, notifytest.Accept)
	for what, c := range map[string]struct {
		notifier string
		opts     map[string]any
		env      map[string]string
	}{
		"slack without URL":     {"slack", map[string]any{}, nil},
		"slack URL inline":      {"slack", map[string]any{"webhook_url_env": "https://hooks.slack.com/services/T0/B0/x"}, nil},
		"slack over http":       {"slack", map[string]any{"webhook_url_env": "H"}, map[string]string{"H": "http://hooks.example.com" + hookPath}},
		"mattermost unset var":  {"mattermost", map[string]any{"webhook_url_env": "UNSET"}, nil},
		"matrix room alias":     {"matrix", map[string]any{"homeserver": "https://m.example.org", "room": "#ops:example.org", "token_env": "T"}, map[string]string{"T": "x"}},
		"matrix room with path": {"matrix", map[string]any{"homeserver": "https://m.example.org", "room": "!a/../b:example.org", "token_env": "T"}, map[string]string{"T": "x"}},
		"matrix without token":  {"matrix", map[string]any{"homeserver": "https://m.example.org", "room": room}, nil},
	} {
		_, err := chatChannel(t, c.notifier, r, c.opts, c.env)
		if err == nil {
			t.Errorf("%s: must be refused", what)
		} else if strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "hooks.example.com") {
			t.Errorf("%s: the error repeats the webhook URL: %v", what, err)
		}
	}
}
