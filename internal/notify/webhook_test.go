package notify_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/notify"
	"github.com/nocs90/shieldmon/internal/notify/notifytest"
)

const webhookSecret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw" // the Standard Webhooks test key

func webhookChannel(t *testing.T, r *notifytest.Receiver, secret string) (notify.Channel, error) {
	t.Helper()
	chs, err := notify.NewChannels([]notify.ChannelConfig{{
		Name: "hook", Notifier: "webhook", Options: map[string]any{"url": r.URL + "/shieldmon", "secret_env": "HOOK_SECRET"},
	}}, notify.Spec{Transport: r.Client.Transport, Env: func(k string) string {
		if k == "HOOK_SECRET" {
			return secret
		}
		return ""
	}})
	if err != nil {
		return notify.Channel{}, err
	}
	return chs[0], nil
}

func mustWebhook(t *testing.T, r *notifytest.Receiver) notify.Notifier {
	t.Helper()
	ch, err := webhookChannel(t, r, webhookSecret)
	if err != nil {
		t.Fatal(err)
	}
	return ch.Sender
}

func TestWebhookConformance(t *testing.T) {
	ok := notifytest.NewReceiver(t, notifytest.Accept)
	redirect := notifytest.NewReceiver(t, notifytest.Redirect)
	notifytest.CheckNotifier(t, notifytest.Fixture{
		Name:        "webhook",
		Notifier:    mustWebhook(t, ok),
		Received:    ok.Bodies,
		Failing:     mustWebhook(t, notifytest.NewReceiver(t, notifytest.Reject)),
		Hanging:     mustWebhook(t, notifytest.NewReceiver(t, notifytest.Hang)),
		Redirecting: mustWebhook(t, redirect),
		Followed:    redirect.Followed,
		Secret:      webhookSecret,
	})
}

// TestWebhookSignatureVerifies checks a receiver can verify what is sent, as a Standard
// Webhooks library would, and that the ID is stable across retries of the same events.
func TestWebhookSignatureVerifies(t *testing.T) {
	r := notifytest.NewReceiver(t, notifytest.Accept)
	n := mustWebhook(t, r)
	sentAt := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	m := notify.Message{Channel: "hook", Events: notifytest.HostileEvents()[:1], SentAt: sentAt}
	for range 2 {
		if err := n.Send(context.Background(), m); err != nil {
			t.Fatal(err)
		}
	}
	h, bodies := r.Headers(), r.Bodies()
	id, stamp := h[0].Get("Webhook-Id"), h[0].Get("Webhook-Timestamp")
	if !strings.HasPrefix(id, "msg_") || h[1].Get("Webhook-Id") != id {
		t.Errorf("webhook-id %q must be stable across retries (%q)", id, h[1].Get("Webhook-Id"))
	}
	if stamp != strconv.FormatInt(sentAt.Unix(), 10) {
		t.Errorf("webhook-timestamp = %q", stamp)
	}
	key := testKey(t)
	if got, want := h[0].Get("Webhook-Signature"), "v1,"+notify.WebhookSignature(key, id, stamp, []byte(bodies[0])); got != want {
		t.Errorf("signature %q does not verify (want %q)", got, want)
	}
	if h[0].Get("Content-Type") != "application/json" {
		t.Errorf("content type %q", h[0].Get("Content-Type"))
	}
	var payload struct {
		Version int            `json:"version"`
		Subject string         `json:"subject"`
		Events  []notify.Event `json:"events"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &payload); err != nil || payload.Version != 1 || len(payload.Events) != 1 ||
		payload.Events[0].Finding.VulnID != "CVE-2024-3094" || !strings.HasPrefix(payload.Subject, "ShieldMon: ") {
		t.Errorf("payload %v: %s", err, bodies[0])
	}
}

// TestWebhookSignatureVector is the example of the Standard Webhooks specification.
func TestWebhookSignatureVector(t *testing.T) {
	key := testKey(t)
	got := notify.WebhookSignature(key, "msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330", []byte(`{"test": 2432232314}`))
	if got != "g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Errorf("signature = %s", got)
	}
}

func TestWebhookRefusesWeakConfiguration(t *testing.T) {
	r := notifytest.NewReceiver(t, notifytest.Accept)
	for what, secret := range map[string]string{
		"no secret":      "",
		"short secret":   "too-short",
		"invalid whsec_": "whsec_!!!not-base64!!!",
	} {
		if _, err := webhookChannel(t, r, secret); err == nil {
			t.Errorf("%s: must be refused", what)
		}
	}
	_, err := notify.NewChannels([]notify.ChannelConfig{{Name: "x", Notifier: "webhook", Options: map[string]any{"url": "https://h.example"}}}, notify.Spec{})
	if err == nil || !strings.Contains(err.Error(), "secret_env is required") {
		t.Errorf("unsigned webhooks are refused: %v", err)
	}
	if h := r.Headers(); len(h) != 0 {
		t.Error("nothing is sent while constructing")
	}
}

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(webhookSecret, "whsec_"))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
