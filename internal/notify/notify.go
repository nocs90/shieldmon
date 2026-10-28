// Package notify sends monitoring events to people through channels: webhooks, e-mail,
// chat, issue trackers (docs/adr/0015-notifications.md). Notifiers are plugins, selected by
// configuration; the engine decides what to send and records what was sent.
package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/nocs90/shieldmon/internal/redact"
)

// Kind is the kind of an event; channels subscribe to kinds.
type Kind string

const (
	FindingNewKEV      Kind = "finding_new_kev"
	FindingNewCritical Kind = "finding_new_critical"
	SLABreached        Kind = "sla_breached"
	SLADueSoon         Kind = "sla_due_soon"
	HealthOpened       Kind = "health_opened"
	// FindingFixed is good news, and what lets an issue tracker close its issue: opt-in.
	FindingFixed Kind = "finding_fixed"
)

// Kinds lists every kind, most urgent first: the order of events in a message.
var Kinds = []Kind{FindingNewKEV, FindingNewCritical, SLABreached, SLADueSoon, HealthOpened, FindingFixed}

// DefaultKinds are what a channel that lists no events receives (unless its notifier says
// otherwise): the alerts.
var DefaultKinds = []Kind{FindingNewKEV, FindingNewCritical, SLABreached, SLADueSoon, HealthOpened}

// ParseKind validates a kind name.
func ParseKind(v string) (Kind, error) {
	for _, k := range Kinds {
		if string(k) == v {
			return k, nil
		}
	}
	return "", fmt.Errorf("unknown event %q (known: %s)", v, kindNames())
}

// Summary is a short description of the kind, for subjects and titles.
func (k Kind) Summary() string {
	switch k {
	case FindingNewKEV:
		return "New known exploited vulnerability"
	case FindingNewCritical:
		return "New critical vulnerability"
	case SLABreached:
		return "Remediation deadline passed"
	case SLADueSoon:
		return "Remediation deadline approaching"
	case HealthOpened:
		return "Monitoring problem"
	case FindingFixed:
		return "Vulnerability fixed"
	}
	return string(k)
}

// Finding is the finding an event is about. Text fields come from scanner output: hostile.
type Finding struct {
	ID int64 `json:"id"`
	// Lineage is the first finding of the problem, followed across digests of a target.
	Lineage       int64     `json:"lineage"`
	VulnID        string    `json:"vuln_id"`
	Aliases       []string  `json:"aliases,omitempty"`
	Title         string    `json:"title,omitempty"`
	Severity      string    `json:"severity"`
	KEV           bool      `json:"kev"`
	CVSS          float64   `json:"cvss,omitempty"`
	EPSS          float64   `json:"epss,omitempty"`
	Package       string    `json:"package"`
	Version       string    `json:"version"`
	PURL          string    `json:"purl"`
	FixVersions   []string  `json:"fix_versions,omitempty"`
	Digest        string    `json:"digest"`
	Targets       []string  `json:"targets,omitempty"`
	State         string    `json:"state"`
	FirstDetected time.Time `json:"first_detected"`
	SLADue        time.Time `json:"sla_due,omitzero"`
}

// Health is the health finding an event is about.
type Health struct {
	Check     string    `json:"check"`
	Subject   string    `json:"subject"`
	Severity  string    `json:"severity"`
	Detail    string    `json:"detail,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
}

// Event is something to tell people about. Key identifies it across cycles: an event is
// sent to a channel at most once.
type Event struct {
	Key     string   `json:"key"`
	Kind    Kind     `json:"kind"`
	Finding *Finding `json:"finding,omitempty"`
	Health  *Health  `json:"health,omitempty"`
	// Remaining is, for finding_fixed, how many active findings still have the vulnerability
	// on the finding's targets (in other packages): 0 means it is gone from them.
	Remaining int `json:"remaining,omitempty"`
}

// Title is a one-line description of the event (unescaped: notifiers escape for their
// medium).
func (e Event) Title() string {
	switch {
	case e.Finding != nil:
		f := e.Finding
		return fmt.Sprintf("%s: %s in %s %s (%s)", e.Kind.Summary(), f.VulnID, f.Package, f.Version, f.Severity)
	case e.Health != nil:
		return fmt.Sprintf("%s: %s on %s", e.Kind.Summary(), e.Health.Check, e.Health.Subject)
	}
	return e.Kind.Summary()
}

// Lines are the details of the event, one per line (unescaped).
func (e Event) Lines() []string {
	var out []string
	if f := e.Finding; f != nil {
		if f.Title != "" {
			out = append(out, f.Title)
		}
		targets := "digest " + f.Digest
		if len(f.Targets) > 0 {
			targets = strings.Join(f.Targets, ", ") + " (" + f.Digest + ")"
		}
		out = append(out, "Image: "+targets)
		risk := "Severity " + f.Severity
		if f.CVSS > 0 {
			risk += fmt.Sprintf(", CVSS %.1f", f.CVSS)
		}
		if f.EPSS > 0 {
			risk += fmt.Sprintf(", EPSS %.1f%%", f.EPSS*100)
		}
		if f.KEV {
			risk += ", in CISA KEV"
		}
		out = append(out, risk)
		if len(f.FixVersions) > 0 {
			out = append(out, "Fixed in: "+strings.Join(f.FixVersions, ", "))
		} else {
			out = append(out, "No fix available yet")
		}
		out = append(out, "First detected: "+day(f.FirstDetected))
		if !f.SLADue.IsZero() {
			out = append(out, "Remediation due: "+day(f.SLADue))
		}
		if e.Kind == FindingFixed {
			if e.Remaining > 0 {
				out = append(out, fmt.Sprintf("Still present in %d other package(s) of the image", e.Remaining))
			} else {
				out = append(out, "No longer present in the image: closed by scan evidence")
			}
		}
		out = append(out, fmt.Sprintf("Finding #%d (state %s): shieldmon findings show %d", f.ID, f.State, f.ID))
	}
	if h := e.Health; h != nil {
		if h.Detail != "" {
			out = append(out, h.Detail)
		}
		out = append(out, "Severity "+h.Severity+", since "+h.FirstSeen.UTC().Format(time.RFC3339), "See: shieldmon health")
	}
	return out
}

func day(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// Message is what a notifier sends: one event, or every event of a cycle in digest mode.
type Message struct {
	// Channel is the configured channel name.
	Channel string `json:"channel"`
	// Digest is true for a cycle summary, which may hold any number of events.
	Digest bool `json:"digest"`
	// Test is true for 'shieldmon notify test': no event, check the channel works.
	Test   bool    `json:"test,omitempty"`
	Events []Event `json:"events"`
	// SentAt is when the message was built (UTC).
	SentAt time.Time `json:"sent_at"`
}

// Subject is a one-line summary of the message (unescaped).
func (m Message) Subject() string {
	switch {
	case m.Test:
		return "ShieldMon test notification for channel " + m.Channel
	case len(m.Events) == 1 && !m.Digest:
		return "ShieldMon: " + m.Events[0].Title()
	}
	counts := map[Kind]int{}
	for _, e := range m.Events {
		counts[e.Kind]++
	}
	var parts []string
	for _, k := range Kinds {
		if n := counts[k]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ReplaceAll(string(k), "_", " ")))
		}
	}
	return "ShieldMon digest: " + strings.Join(parts, ", ")
}

// Notifier sends messages to one channel. Send must honour ctx, never follow a redirect to
// another host with a credential, and return errors that hold no credential.
type Notifier interface {
	Send(ctx context.Context, m Message) error
}

// Plugin describes a notifier. Notifiers register themselves from an init function, like
// scanner plugins (ADR 0008).
type Plugin struct {
	// Name is the value of notifications.channels[].notifier that selects the notifier.
	Name        string
	Description string
	// Options lists the keys accepted under notifications.channels[].options.
	Options []string
	// Kinds are the event kinds the notifier handles; nil for every kind. A channel that
	// lists another kind is refused.
	Kinds []Kind
	// Defaults are what a channel that lists no events receives; nil for DefaultKinds.
	Defaults []Kind
	// NoDigest marks notifiers that act on each event (issue trackers): digest is refused.
	NoDigest bool
	New      func(Spec) (Notifier, error)
}

// Spec is what a notifier receives at construction time.
type Spec struct {
	Channel string
	Options Options
	// Env reads environment variables; os.Getenv unless a test replaces it.
	Env func(string) string
	// Transport carries HTTP requests; http.DefaultTransport unless a test replaces it.
	Transport http.RoundTripper
	// TLS is the base TLS client configuration of non-HTTP notifiers; nil uses the system
	// roots (tests set RootCAs).
	TLS *tls.Config
}

// Options are notifier settings from configuration. Values are plain settings, never
// credentials: a credential is passed by naming an environment variable (an option ending in
// "_env").
type Options map[string]any

// String returns a string option or def when unset.
func (o Options) String(key, def string) (string, error) {
	v, ok := o[key]
	if !ok {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("option %s: want a string, got %T", key, v)
	}
	return s, nil
}

// Strings returns a list-of-strings option (a single string is a list of one).
func (o Options) Strings(key string) ([]string, error) {
	switch v := o[key].(type) {
	case nil:
		return nil, nil
	case string:
		return []string{v}, nil
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("option %s: want strings, got %T", key, x)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("option %s: want a list of strings, got %T", key, v)
	}
}

// Bool returns a boolean option or def when unset.
func (o Options) Bool(key string, def bool) (bool, error) {
	v, ok := o[key]
	if !ok {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("option %s: want true or false, got %T", key, v)
	}
	return b, nil
}

// Int returns an integer option or def when unset.
func (o Options) Int(key string, def int) (int, error) {
	switch v := o[key].(type) {
	case nil:
		return def, nil
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		if v == float64(int(v)) {
			return int(v), nil
		}
	}
	return 0, fmt.Errorf("option %s: want an integer, got %v", key, o[key])
}

// Secret returns the value of the environment variable named by option key. It is an error
// when the option names a variable that is unset or empty; "" when the option is unset.
func (s Spec) Secret(key string) (string, error) {
	envName, err := s.Options.String(key, "")
	if err != nil || envName == "" {
		return "", err
	}
	v := s.env()(envName)
	if v == "" {
		return "", fmt.Errorf("option %s: environment variable %s is not set", key, envName)
	}
	return v, nil
}

func (s Spec) env() func(string) string {
	if s.Env != nil {
		return s.Env
	}
	return os.Getenv
}

var (
	pluginsMu sync.RWMutex
	plugins   = map[string]Plugin{}
)

// RegisterNotifier makes a notifier available. It panics on duplicate or invalid
// registrations, which are programming errors.
func RegisterNotifier(p Plugin) {
	pluginsMu.Lock()
	defer pluginsMu.Unlock()
	if p.Name == "" || p.Description == "" || p.New == nil {
		panic("notify: RegisterNotifier requires Name, Description and New")
	}
	if _, dup := plugins[p.Name]; dup {
		panic("notify: duplicate notifier " + p.Name)
	}
	plugins[p.Name] = p
}

// Notifiers returns all registered notifiers sorted by name.
func Notifiers() []Plugin {
	pluginsMu.RLock()
	defer pluginsMu.RUnlock()
	out := make([]Plugin, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LookupNotifier returns a registered notifier.
func LookupNotifier(name string) (Plugin, bool) {
	pluginsMu.RLock()
	defer pluginsMu.RUnlock()
	p, ok := plugins[name]
	return p, ok
}

// ChannelConfig is one entry of notifications.channels.
type ChannelConfig struct {
	Name     string
	Notifier string
	// Events the channel receives; every kind when empty.
	Events  []string
	Digest  bool
	Options map[string]any
}

// Channel is a configured, constructed notification channel.
type Channel struct {
	Name     string
	Notifier string
	Kinds    []Kind
	Digest   bool
	Sender   Notifier
}

// Wants reports whether the channel receives events of kind k.
func (c Channel) Wants(k Kind) bool { return slices.Contains(c.Kinds, k) }

var channelNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// NewChannels validates the configured channels and builds their notifiers, each with base
// (environment, transports: zero in production) completed by its name and options.
func NewChannels(cfgs []ChannelConfig, base Spec) ([]Channel, error) {
	var out []Channel
	seen := map[string]bool{}
	for i, c := range cfgs {
		where := fmt.Sprintf("notifications.channels[%d]", i)
		if !channelNameRE.MatchString(c.Name) {
			return nil, fmt.Errorf("%s: name %q: want lowercase letters, digits, - and _ (at most 64)", where, c.Name)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("%s: duplicate channel name %q", where, c.Name)
		}
		seen[c.Name] = true
		p, ok := LookupNotifier(c.Notifier)
		if !ok {
			return nil, fmt.Errorf("%s: unknown notifier %q (registered: %s)", where, c.Notifier, notifierNames())
		}
		if c.Digest && p.NoDigest {
			return nil, fmt.Errorf("%s: notifier %s acts on each event: digest does not apply", where, c.Notifier)
		}
		kinds := p.Defaults
		if kinds == nil {
			kinds = DefaultKinds
		}
		kinds = slices.DeleteFunc(slices.Clone(kinds), func(k Kind) bool { return p.Kinds != nil && !slices.Contains(p.Kinds, k) })
		if len(c.Events) > 0 {
			kinds = nil
			for _, ev := range c.Events {
				k, err := ParseKind(ev)
				if err != nil {
					return nil, fmt.Errorf("%s.events: %w", where, err)
				}
				if p.Kinds != nil && !slices.Contains(p.Kinds, k) {
					return nil, fmt.Errorf("%s.events: notifier %s does not handle %s", where, c.Notifier, k)
				}
				if !slices.Contains(kinds, k) {
					kinds = append(kinds, k)
				}
			}
		}
		if err := validOptions(p, c.Options); err != nil {
			return nil, fmt.Errorf("%s.options: %w", where, err)
		}
		spec := base
		spec.Channel, spec.Options = c.Name, c.Options
		n, err := p.New(spec)
		if err != nil {
			return nil, fmt.Errorf("%s: notifier %s: %s", where, c.Notifier, redact.Error(err))
		}
		out = append(out, Channel{Name: c.Name, Notifier: c.Notifier, Kinds: kinds, Digest: c.Digest, Sender: n})
	}
	return out, nil
}

// validOptions rejects unknown keys and values that look like credentials.
func validOptions(p Plugin, opts map[string]any) error {
	for k, v := range opts {
		if !slices.Contains(p.Options, k) {
			return fmt.Errorf("unknown option %q (known: %s)", k, strings.Join(p.Options, ", "))
		}
		if s, ok := v.(string); ok && redact.String(s) != s {
			return fmt.Errorf("option %s looks like a credential: put it in an environment variable and name that variable instead", k)
		}
	}
	return nil
}

func notifierNames() string {
	var out []string
	for _, p := range Notifiers() {
		out = append(out, p.Name)
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ", ")
}

func kindNames() string {
	out := make([]string, len(Kinds))
	for i, k := range Kinds {
		out[i] = string(k)
	}
	return strings.Join(out, ", ")
}

// Bounds of one cycle's sending, per channel: a backlog beyond them waits for the next cycle.
const (
	MaxEventsPerMessage = 100
	MaxMessagesPerCycle = 50
	// SendTimeout bounds one Send.
	SendTimeout = 30 * time.Second
)

// Sort orders events most urgent first, then by key: the order they are sent in.
func Sort(events []Event) {
	rank := func(k Kind) int {
		if i := slices.Index(Kinds, k); i >= 0 {
			return i
		}
		return len(Kinds)
	}
	sort.SliceStable(events, func(i, j int) bool {
		if ri, rj := rank(events[i].Kind), rank(events[j].Kind); ri != rj {
			return ri < rj
		}
		return events[i].Key < events[j].Key
	})
}

// Dispatch sends pending events to the channel: one message per event, or digests of up to
// MaxEventsPerMessage events, at most MaxMessagesPerCycle messages. It stops at the first
// failure and returns the keys of the events sent before it; the error is redacted.
func Dispatch(ctx context.Context, ch Channel, pending []Event, now time.Time) ([]string, error) {
	pending = slices.Clone(pending)
	Sort(pending)
	size := 1
	if ch.Digest {
		size = MaxEventsPerMessage
	}
	var sent []string
	for msgs := 0; len(pending) > 0 && msgs < MaxMessagesPerCycle; msgs++ {
		batch := pending[:min(size, len(pending))]
		pending = pending[len(batch):]
		m := Message{Channel: ch.Name, Digest: ch.Digest, Events: batch, SentAt: now.UTC()}
		if err := send(ctx, ch, m); err != nil {
			return sent, err
		}
		for _, e := range batch {
			sent = append(sent, e.Key)
		}
	}
	return sent, nil
}

// Test sends a test message to the channel.
func Test(ctx context.Context, ch Channel, now time.Time) error {
	return send(ctx, ch, Message{Channel: ch.Name, Test: true, SentAt: now.UTC()})
}

func send(ctx context.Context, ch Channel, m Message) error {
	ctx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	err := ch.Sender.Send(ctx, m)
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
		return fmt.Errorf("channel %s: no answer within %s", ch.Name, SendTimeout)
	}
	return fmt.Errorf("channel %s: %s", ch.Name, redact.Error(err))
}

// Clean makes hostile text safe for one line of plain text: control characters (CR and LF
// included) and bidirectional overrides become \uXXXX, and the result is cut to max runes.
func Clean(s string, maxRunes int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxRunes {
			b.WriteString("…")
			break
		}
		n++
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
