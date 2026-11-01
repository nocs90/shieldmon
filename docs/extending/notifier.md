# Writing a notifier

A notifier delivers messages to one kind of channel: a webhook, e-mail, a chat room, an
issue tracker ([ADR 0015](../adr/0015-notifications.md)). The engine decides what to send
and records what was sent; a notifier only delivers. It never sees the store, never decides
whether an event is new, and never retries by itself: a failed `Send` is retried by the
next monitoring cycle.

## 1. Implement `notify.Notifier`

```go
// internal/notify/ntfy.go
type ntfyNotifier struct {
	url    *url.URL
	token  string // from the environment, never from config
	client *http.Client
}

func (n ntfyNotifier) Send(ctx context.Context, m notify.Message) error {
	var b strings.Builder
	for _, e := range m.Events {
		// Event text comes from scanner output: escape it for the medium.
		b.WriteString(notify.Clean(e.Title(), 300) + "\n")
	}
	return notify.Post(ctx, n.client, n.url, "text/plain; charset=utf-8", []byte(b.String()),
		http.Header{"Authorization": {"Bearer " + n.token}, "Title": {notify.Clean(m.Subject(), 200)}})
}
```

A `Message` holds one event, or every event of a cycle when `Digest` is true, or none when
`Test` is true (`shieldmon notify test`). `Event.Title`, `Event.Lines` and
`Message.Subject` give plain text to build on; they are **not escaped**:

- JSON: `encoding/json` escapes;
- one line of plain text, e-mail headers: `notify.Clean` (control characters, CR/LF and
  bidirectional overrides become `\uXXXX`; bounded length);
- Markdown, HTML, chat markup: escape the medium's metacharacters, and neutralise mentions
  (`@channel`, `@room`, `<!here>`).

HTTP notifiers use `notify.HTTPClient` (no redirects, timeout), `notify.ParseURL` for URL
options (https; http only to localhost; no credentials in the URL) and `notify.Post` or
`notify.Do`, whose errors name the host and status only — never the URL, which may itself
be a credential, nor the answer, which may echo the request.

## 2. Register it

```go
func init() {
	notify.RegisterNotifier(notify.Plugin{
		Name:        "ntfy",
		Description: "ntfy topic over HTTPS",
		Options:     []string{"url", "token_env"},
		New: func(s notify.Spec) (notify.Notifier, error) {
			raw, err := s.Options.String("url", "")
			…
			u, err := notify.ParseURL("url", raw)
			…
			token, err := s.Secret("token_env")
			…
			return ntfyNotifier{url: u, token: token, client: notify.HTTPClient(s)}, nil
		},
	})
}
```

A notifier that only makes sense for some events declares them: `Kinds` (a channel listing
another kind is refused), `Defaults` (what a channel listing none receives, instead of
`notify.DefaultKinds`), and `NoDigest` for notifiers that act on each event, such as issue
trackers.

Configuration selects it per channel:

```yaml
notifications:
  channels:
    - name: oncall
      notifier: ntfy
      events: [finding_new_kev, health_opened]
      options: { url: https://ntfy.example.com/shieldmon, token_env: NTFY_TOKEN }
```

Unknown option keys are rejected at startup, and so is any option value that looks like a
credential: credentials only ever come from environment variables named by `*_env` options,
read with `Spec.Secret` (an error names the variable when it is unset).

## 3. Prove it

`notifytest.CheckNotifier` with fake endpoints (`notifytest.NewReceiver` is an HTTPS
endpoint that accepts, rejects while echoing the request, hangs, or redirects):

- registered with a description; credential options end in `_env`;
- each hostile event (`notifytest.HostileEvents`) arrives, a digest mentions every event, a
  test message is delivered, and no payload holds an injected header line or the credential;
- cancellation and deadlines are honoured, a redirect is not followed, and no error contains
  the credential.
