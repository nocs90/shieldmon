package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func init() {
	RegisterNotifier(Plugin{
		Name:        "slack",
		Description: "Slack incoming webhook",
		Options:     []string{"webhook_url_env"},
		New: func(s Spec) (Notifier, error) {
			return newChatWebhook(s, slackText)
		},
	})
	RegisterNotifier(Plugin{
		Name:        "mattermost",
		Description: "Mattermost incoming webhook",
		Options:     []string{"webhook_url_env"},
		New: func(s Spec) (Notifier, error) {
			return newChatWebhook(s, mattermostText)
		},
	})
	RegisterNotifier(Plugin{
		Name:        "matrix",
		Description: "Matrix room, as m.notice events through the client-server API",
		Options:     []string{"homeserver", "room", "token_env"},
		New:         newMatrix,
	})
}

// Bounds of chat messages, in runes of event text: a digest beyond them lists how many
// events it leaves out (they are in 'shieldmon findings' and 'shieldmon health').
const (
	chatBudget       = 12000
	matrixBudget     = 30000
	chatLineRunes    = 300
	chatDigestRunes  = 150
	chatOmittedLabel = "… and %d more event(s): see 'shieldmon findings list' and 'shieldmon health'"
)

// chatHeading is the first line of a chat message. It holds only ShieldMon's own text (kind
// summaries, counts, the validated channel name), never scanner output, so that it can be
// rendered as markup.
func chatHeading(m Message) string {
	switch {
	case m.Test:
		return "ShieldMon test notification for channel " + m.Channel
	case len(m.Events) == 1 && !m.Digest:
		return "ShieldMon: " + m.Events[0].Kind.Summary()
	}
	return m.Subject() // a digest's subject is counts per kind
}

// chatBody is the event text of a chat message: hostile, cleaned line by line, to be rendered
// as preformatted text only. A single event gets its details; a digest one line per event,
// within budget runes.
func chatBody(m Message, budget int) string {
	if m.Test {
		return "If you see this, the channel works."
	}
	var lines []string
	if len(m.Events) == 1 && !m.Digest {
		e := m.Events[0]
		lines = append(lines, Clean(e.Title(), chatLineRunes))
		for _, l := range e.Lines() {
			lines = append(lines, Clean(l, chatLineRunes))
		}
		return strings.Join(lines, "\n")
	}
	used := 0
	for i, e := range m.Events {
		l := "- " + Clean(e.Title(), chatDigestRunes)
		if used+len([]rune(l)) > budget {
			lines = append(lines, fmt.Sprintf(chatOmittedLabel, len(m.Events)-i))
			break
		}
		used += len([]rune(l)) + 1
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n")
}

// codeSafe keeps text inside a Markdown code block: a backtick could close it.
func codeSafe(s string) string { return strings.ReplaceAll(s, "`", "'") }

// slackEscape escapes the three characters Slack parses as control sequences (links,
// mentions such as <!channel>), everywhere in a message, code blocks included.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// slackText renders a message for Slack: event text in a code block, where no formatting
// applies, with control sequences escaped. Mentions need <!…> sequences, which cannot
// survive the escaping, and link_names is never set.
func slackText(m Message) map[string]any {
	text := "*" + slackEscape(chatHeading(m)) + "*\n```\n" + slackEscape(codeSafe(chatBody(m, chatBudget))) + "\n```"
	return map[string]any{"text": text}
}

// mattermostText renders a message for Mattermost: event text in a code block, where
// Markdown, HTML and @-mentions (@channel, @all, @here) do not apply.
func mattermostText(m Message) map[string]any {
	text := "**" + chatHeading(m) + "**\n```\n" + codeSafe(chatBody(m, chatBudget)) + "\n```"
	return map[string]any{"text": text}
}

// chatWebhook posts to an incoming webhook whose URL is the credential: it comes from an
// environment variable and never appears in errors.
type chatWebhook struct {
	url    *url.URL
	render func(Message) map[string]any
	client *http.Client
}

func newChatWebhook(s Spec, render func(Message) map[string]any) (Notifier, error) {
	if v, _ := s.Options.String("webhook_url_env", ""); v == "" {
		return nil, errors.New("option webhook_url_env is required: the webhook URL is a credential")
	}
	raw, err := s.Secret("webhook_url_env")
	if err != nil {
		return nil, err
	}
	u, err := ParseURL("webhook_url_env", raw)
	if err != nil {
		return nil, err
	}
	return &chatWebhook{url: u, render: render, client: HTTPClient(s)}, nil
}

func (w *chatWebhook) Send(ctx context.Context, m Message) error {
	body, err := json.Marshal(w.render(m))
	if err != nil {
		return err
	}
	return Post(ctx, w.client, w.url, "application/json", body, nil)
}

// matrixRoomRE is a room ID (!opaque:server); aliases (#room:server) would need resolving.
var matrixRoomRE = regexp.MustCompile(`^![^:/\s]{1,200}:[A-Za-z0-9.:\[\]-]{1,255}$`)

// matrix sends m.notice events (the message type for bots: clients do not answer them) to
// one room, with an access token from the environment.
type matrix struct {
	homeserver *url.URL
	room       string
	token      string
	client     *http.Client
}

func newMatrix(s Spec) (Notifier, error) {
	raw, err := s.Options.String("homeserver", "")
	if err != nil {
		return nil, err
	}
	hs, err := ParseURL("homeserver", raw)
	if err != nil {
		return nil, err
	}
	room, err := s.Options.String("room", "")
	if err != nil {
		return nil, err
	}
	if !matrixRoomRE.MatchString(room) {
		return nil, fmt.Errorf("option room: want a room ID (!opaque:server), got %q", Clean(room, 100))
	}
	if v, _ := s.Options.String("token_env", ""); v == "" {
		return nil, errors.New("option token_env is required")
	}
	token, err := s.Secret("token_env")
	if err != nil {
		return nil, err
	}
	return &matrix{homeserver: hs, room: room, token: token, client: HTTPClient(s)}, nil
}

func (x *matrix) Send(ctx context.Context, m Message) error {
	heading, body := chatHeading(m), chatBody(m, matrixBudget)
	content, err := json.Marshal(map[string]any{
		"msgtype":        "m.notice",
		"body":           heading + "\n" + body,
		"format":         "org.matrix.custom.html",
		"formatted_body": "<p><strong>" + html.EscapeString(heading) + "</strong></p><pre><code>" + html.EscapeString(body) + "</code></pre>",
		// Intentional mentions: mention nobody, so that text such as @room in scanner output
		// does not notify the room.
		"m.mentions": map[string]any{},
	})
	if err != nil {
		return err
	}
	// The transaction ID is the delivery ID: a retry of the same events is deduplicated by
	// the homeserver.
	txn := DeliveryID(m)
	const send = "/_matrix/client/v3/rooms/%s/send/m.room.message/%s"
	u := *x.homeserver
	base := strings.TrimSuffix(u.Path, "/")
	u.Path = base + fmt.Sprintf(send, x.room, txn)
	u.RawPath = (&url.URL{Path: base}).EscapedPath() + fmt.Sprintf(send, url.PathEscape(x.room), txn)
	return Request(ctx, x.client, http.MethodPut, &u, "application/json", content, http.Header{"Authorization": {"Bearer " + x.token}})
}
