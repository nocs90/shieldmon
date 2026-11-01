package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// minWebhookSecret is the shortest signing key accepted, in bytes (Standard Webhooks: 24-64).
const minWebhookSecret = 24

func init() {
	RegisterNotifier(Plugin{
		Name:        "webhook",
		Description: "JSON over HTTPS, signed per Standard Webhooks (HMAC-SHA256 over id, timestamp and body)",
		Options:     []string{"url", "secret_env"},
		New:         newWebhook,
	})
}

// webhook posts each message as JSON. Receivers verify the signature with any Standard
// Webhooks library (https://www.standardwebhooks.com): headers webhook-id (stable across
// retries of the same events, for deduplication), webhook-timestamp (Unix seconds, to refuse
// replays) and webhook-signature ("v1," + base64 HMAC-SHA256 of "id.timestamp.body").
type webhook struct {
	url    *url.URL
	key    []byte
	client *http.Client
}

func newWebhook(s Spec) (Notifier, error) {
	raw, err := s.Options.String("url", "")
	if err != nil {
		return nil, err
	}
	u, err := ParseURL("url", raw)
	if err != nil {
		return nil, err
	}
	if v, _ := s.Options.String("secret_env", ""); v == "" {
		return nil, errors.New("option secret_env is required: payloads are always signed")
	}
	secret, err := s.Secret("secret_env")
	if err != nil {
		return nil, err
	}
	key, err := webhookKey(secret)
	if err != nil {
		return nil, err
	}
	return &webhook{url: u, key: key, client: HTTPClient(s)}, nil
}

// webhookKey decodes a Standard Webhooks secret ("whsec_" + base64) or takes any other value
// as raw bytes.
func webhookKey(secret string) ([]byte, error) {
	key := []byte(secret)
	if b64, ok := strings.CutPrefix(secret, "whsec_"); ok {
		var err error
		if key, err = base64.StdEncoding.DecodeString(b64); err != nil {
			return nil, errors.New("option secret_env: the whsec_ secret is not valid base64")
		}
	}
	if len(key) < minWebhookSecret {
		return nil, fmt.Errorf("option secret_env: the secret must be at least %d bytes", minWebhookSecret)
	}
	return key, nil
}

// webhookPayload is the JSON body: the message, with a version for receivers and the
// subject a human would read.
type webhookPayload struct {
	Version int    `json:"version"`
	Subject string `json:"subject"`
	Message
}

func (w *webhook) Send(ctx context.Context, m Message) error {
	body, err := json.Marshal(webhookPayload{Version: 1, Subject: m.Subject(), Message: m})
	if err != nil {
		return err
	}
	id := DeliveryID(m)
	stamp := strconv.FormatInt(m.SentAt.Unix(), 10)
	return Post(ctx, w.client, w.url, "application/json", body, http.Header{
		"Webhook-Id":        {id},
		"Webhook-Timestamp": {stamp},
		"Webhook-Signature": {"v1," + WebhookSignature(w.key, id, stamp, body)},
	})
}

// WebhookSignature is base64(HMAC-SHA256(key, id + "." + timestamp + "." + body)).
func WebhookSignature(key []byte, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// DeliveryID identifies a message by its channel and events: a message retried in a later
// cycle with the same events has the same ID, so that receivers can drop duplicates.
func DeliveryID(m Message) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%t\x00%t\x00", m.Channel, m.Digest, m.Test)
	if m.Test {
		fmt.Fprintf(h, "%d\x00", m.SentAt.UnixNano())
	}
	for _, e := range m.Events {
		fmt.Fprintf(h, "%s\x00", e.Key)
	}
	return "msg_" + hex.EncodeToString(h.Sum(nil))[:32]
}
