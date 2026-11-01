package notify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Issue trackers keep one issue per problem group (target, vulnerability): opened (or
// reopened) when the problem is news, commented when its deadline approaches or passes, and
// closed only when ShieldMon closes the finding by scan evidence and nothing of the
// vulnerability is left on the target. They act only where a channel is configured.

// trackerKinds are the events issue trackers act on.
var trackerKinds = []Kind{FindingNewKEV, FindingNewCritical, SLABreached, SLADueSoon, FindingFixed}

const (
	// trackerLabel marks the issues ShieldMon manages; only those are ever read or changed.
	trackerLabel = "shieldmon"
	// trackerMaxIssues bounds the listing: beyond it, ShieldMon refuses to act rather than
	// risk duplicates.
	trackerMaxIssues   = 2000
	trackerPage        = 100
	trackerMaxAnswer   = 4 << 20
	trackerCacheTTL    = 10 * time.Minute
	trackerTitleRunes  = 250
	trackerMarkerStart = "<!-- shieldmon:group="
)

func init() {
	RegisterNotifier(Plugin{
		Name:        "github-issues",
		Description: "one GitHub issue per target and vulnerability, closed on scan evidence",
		Options:     []string{"repo", "api_url", "token_env", "labels"},
		Kinds:       trackerKinds, Defaults: trackerKinds, NoDigest: true,
		New: func(s Spec) (Notifier, error) { return newTracker(s, newGitHubAPI) },
	})
	RegisterNotifier(Plugin{
		Name:        "gitlab-issues",
		Description: "one GitLab issue per target and vulnerability, closed on scan evidence",
		Options:     []string{"project", "api_url", "token_env", "labels"},
		Kinds:       trackerKinds, Defaults: trackerKinds, NoDigest: true,
		New: func(s Spec) (Notifier, error) { return newTracker(s, newGitLabAPI) },
	})
}

// trackedIssue is an issue ShieldMon manages, found by the group marker its body starts with.
type trackedIssue struct {
	Number int64
	Open   bool
	Group  string
}

// trackerAPI is one tracker's REST API.
type trackerAPI interface {
	// list returns the issues labelled trackerLabel, open and closed.
	list(ctx context.Context) ([]trackedIssue, error)
	create(ctx context.Context, title, body string, labels []string) (int64, error)
	comment(ctx context.Context, number int64, body string) error
	setOpen(ctx context.Context, number int64, open bool) error
	// check reads the project: credentials and access, without writing.
	check(ctx context.Context) error
}

type tracker struct {
	api    trackerAPI
	labels []string

	mu       sync.Mutex
	issues   map[string]trackedIssue
	loadedAt time.Time
}

var trackerLabelRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,49}$`)

func newTracker(s Spec, mk func(Spec, *http.Client, string) (trackerAPI, error)) (Notifier, error) {
	if v, _ := s.Options.String("token_env", ""); v == "" {
		return nil, errors.New("option token_env is required")
	}
	token, err := s.Secret("token_env")
	if err != nil {
		return nil, err
	}
	extra, err := s.Options.Strings("labels")
	if err != nil {
		return nil, err
	}
	labels := []string{trackerLabel}
	for _, l := range extra {
		if !trackerLabelRE.MatchString(l) || strings.Contains(l, ",") {
			return nil, fmt.Errorf("option labels: invalid label %q", Clean(l, 60))
		}
		labels = append(labels, l)
	}
	api, err := mk(s, HTTPClient(s), token)
	if err != nil {
		return nil, err
	}
	return &tracker{api: api, labels: labels}, nil
}

func (t *tracker) Send(ctx context.Context, m Message) error {
	if m.Test {
		return t.api.check(ctx)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.load(ctx, m.SentAt); err != nil {
		return err
	}
	for _, e := range m.Events {
		if e.Finding == nil {
			continue
		}
		for _, target := range groupTargets(*e.Finding) {
			if err := t.apply(ctx, e, target); err != nil {
				return err
			}
		}
	}
	return nil
}

// load lists the managed issues, at most once per trackerCacheTTL (a monitoring cycle sends
// one message per event).
func (t *tracker) load(ctx context.Context, now time.Time) error {
	if t.issues != nil && now.Sub(t.loadedAt) < trackerCacheTTL && !now.Before(t.loadedAt) {
		return nil
	}
	list, err := t.api.list(ctx)
	if err != nil {
		return err
	}
	t.issues = map[string]trackedIssue{}
	for _, is := range list {
		// The first issue of a group wins; a duplicate made by hand is left alone.
		if prev, ok := t.issues[is.Group]; !ok || is.Number < prev.Number {
			t.issues[is.Group] = is
		}
	}
	t.loadedAt = now
	return nil
}

func (t *tracker) apply(ctx context.Context, e Event, target string) error {
	f := *e.Finding
	group := groupKey(target, f.VulnID)
	is, exists := t.issues[group]
	text := trackerText(e)
	switch e.Kind {
	case FindingFixed:
		if !exists || !is.Open {
			return nil
		}
		if err := t.api.comment(ctx, is.Number, text); err != nil {
			return err
		}
		if e.Remaining > 0 {
			return nil
		}
		if err := t.api.setOpen(ctx, is.Number, false); err != nil {
			return err
		}
		is.Open = false
	default:
		switch {
		case !exists:
			title := Clean("[ShieldMon] "+f.VulnID+" in "+target, trackerTitleRunes)
			n, err := t.api.create(ctx, title, trackerBody(group, e), t.labels)
			if err != nil {
				return err
			}
			is = trackedIssue{Number: n, Open: true, Group: group}
		case !is.Open:
			if err := t.api.setOpen(ctx, is.Number, true); err != nil {
				return err
			}
			is.Open = true
			if err := t.api.comment(ctx, is.Number, "**Reopened by ShieldMon: the vulnerability is back.**\n\n"+text); err != nil {
				return err
			}
		default:
			if err := t.api.comment(ctx, is.Number, text); err != nil {
				return err
			}
		}
	}
	t.issues[group] = is
	return nil
}

// groupTargets are the targets an event's issue groups are per: the finding's targets, or its
// digest when no target resolves to it any more.
func groupTargets(f Finding) []string {
	if len(f.Targets) > 0 {
		return f.Targets
	}
	return []string{"digest " + f.Digest}
}

func groupKey(target, vulnID string) string {
	sum := sha256.Sum256([]byte(target + "\x00" + vulnID))
	return hex.EncodeToString(sum[:10])
}

// trackerText is a comment: the kind (ShieldMon's own text) and the event in a code block,
// where Markdown, HTML, references (#1) and mentions (@team) do not apply.
func trackerText(e Event) string {
	return "**" + e.Kind.Summary() + "**\n\n```text\n" + codeSafe(chatBody(Message{Events: []Event{e}}, chatBudget)) + "\n```"
}

// trackerBody starts with the group marker, which only ShieldMon writes at that place.
func trackerBody(group string, e Event) string {
	return trackerMarkerStart + group + " -->\n" +
		"ShieldMon opened this issue for a vulnerability in a monitored image. It closes it when a " +
		"scan shows the vulnerability is gone from the image: closing it by hand does not change " +
		"the finding (use `shieldmon findings` to record decisions).\n\n" + trackerText(e)
}

// parseGroup reads the group marker from the first line of an issue body.
func parseGroup(body string) string {
	line, _, _ := strings.Cut(body, "\n")
	g, ok := strings.CutPrefix(strings.TrimSpace(line), trackerMarkerStart)
	if !ok {
		return ""
	}
	g, ok = strings.CutSuffix(g, " -->")
	if !ok || len(g) != 20 || strings.Trim(g, "0123456789abcdef") != "" {
		return ""
	}
	return g
}

// restCall sends a JSON request and decodes a bounded JSON answer into out (nil: ignore it).
func restCall(ctx context.Context, c *http.Client, method string, u *url.URL, header http.Header, in, out any) (http.Header, error) {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s %s: invalid request", method, u.Host)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "shieldmon")
	data, h, err := DoRead(c, req, trackerMaxAnswer)
	if err != nil {
		return nil, err
	}
	if out != nil && json.Unmarshal(data, out) != nil {
		return nil, fmt.Errorf("%s %s: unexpected answer", method, u.Host)
	}
	return h, nil
}

// apiURL joins escaped path segments (already escaped by the caller) to base.
func apiURL(base *url.URL, escaped string, query url.Values) *url.URL {
	u := *base
	prefix := strings.TrimSuffix(base.EscapedPath(), "/")
	raw := prefix + escaped
	if p, err := url.PathUnescape(raw); err == nil {
		u.Path, u.RawPath = p, raw
	}
	u.RawQuery = query.Encode()
	return &u
}

// ---- GitHub ----

var githubRepoRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)

type githubAPI struct {
	base   *url.URL
	repo   string // owner/name, validated
	header http.Header
	client *http.Client
}

func newGitHubAPI(s Spec, c *http.Client, token string) (trackerAPI, error) {
	repo, err := s.Options.String("repo", "")
	if err != nil {
		return nil, err
	}
	if !githubRepoRE.MatchString(repo) || strings.Contains(repo, "..") {
		return nil, fmt.Errorf("option repo: want owner/name, got %q", Clean(repo, 100))
	}
	raw, err := s.Options.String("api_url", "https://api.github.com")
	if err != nil {
		return nil, err
	}
	base, err := ParseURL("api_url", raw)
	if err != nil {
		return nil, err
	}
	return &githubAPI{base: base, repo: repo, client: c, header: http.Header{
		"Authorization":        {"Bearer " + token},
		"Accept":               {"application/vnd.github+json"},
		"X-Github-Api-Version": {"2022-11-28"},
	}}, nil
}

func (g *githubAPI) url(path string, q url.Values) *url.URL {
	owner, name, _ := strings.Cut(g.repo, "/")
	return apiURL(g.base, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+path, q)
}

func (g *githubAPI) list(ctx context.Context) ([]trackedIssue, error) {
	var out []trackedIssue
	for page := 1; ; page++ {
		if (page-1)*trackerPage >= trackerMaxIssues {
			return nil, fmt.Errorf("more than %d issues labelled %s: not acting, to avoid duplicates", trackerMaxIssues, trackerLabel)
		}
		var items []struct {
			Number      int64           `json:"number"`
			State       string          `json:"state"`
			Body        string          `json:"body"`
			PullRequest json.RawMessage `json:"pull_request"`
		}
		q := url.Values{"labels": {trackerLabel}, "state": {"all"}, "per_page": {strconv.Itoa(trackerPage)}, "page": {strconv.Itoa(page)}}
		if _, err := restCall(ctx, g.client, http.MethodGet, g.url("/issues", q), g.header, nil, &items); err != nil {
			return nil, err
		}
		for _, it := range items {
			if group := parseGroup(it.Body); group != "" && it.PullRequest == nil {
				out = append(out, trackedIssue{Number: it.Number, Open: it.State == "open", Group: group})
			}
		}
		if len(items) < trackerPage {
			return out, nil
		}
	}
}

func (g *githubAPI) create(ctx context.Context, title, body string, labels []string) (int64, error) {
	var res struct {
		Number int64 `json:"number"`
	}
	_, err := restCall(ctx, g.client, http.MethodPost, g.url("/issues", nil), g.header,
		map[string]any{"title": title, "body": body, "labels": labels}, &res)
	if err == nil && res.Number <= 0 {
		err = errors.New("github: the created issue has no number")
	}
	return res.Number, err
}

func (g *githubAPI) comment(ctx context.Context, n int64, body string) error {
	_, err := restCall(ctx, g.client, http.MethodPost, g.url(fmt.Sprintf("/issues/%d/comments", n), nil), g.header, map[string]any{"body": body}, nil)
	return err
}

func (g *githubAPI) setOpen(ctx context.Context, n int64, open bool) error {
	state := map[string]any{"state": "closed", "state_reason": "completed"}
	if open {
		state = map[string]any{"state": "open"}
	}
	_, err := restCall(ctx, g.client, http.MethodPatch, g.url(fmt.Sprintf("/issues/%d", n), nil), g.header, state, nil)
	return err
}

func (g *githubAPI) check(ctx context.Context) error {
	_, err := restCall(ctx, g.client, http.MethodGet, g.url("", nil), g.header, nil, nil)
	return err
}

// ---- GitLab ----

var gitlabProjectRE = regexp.MustCompile(`^(?:[0-9]+|[A-Za-z0-9_.][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.][A-Za-z0-9_.-]*)+)$`)

type gitlabAPI struct {
	base    *url.URL
	project string // URL-escaped ID or path
	header  http.Header
	client  *http.Client
}

func newGitLabAPI(s Spec, c *http.Client, token string) (trackerAPI, error) {
	project, err := s.Options.String("project", "")
	if err != nil {
		return nil, err
	}
	if !gitlabProjectRE.MatchString(project) || strings.Contains(project, "..") || len(project) > 255 {
		return nil, fmt.Errorf("option project: want a project ID or group/project path, got %q", Clean(project, 100))
	}
	raw, err := s.Options.String("api_url", "https://gitlab.com")
	if err != nil {
		return nil, err
	}
	base, err := ParseURL("api_url", raw)
	if err != nil {
		return nil, err
	}
	return &gitlabAPI{base: base, project: url.PathEscape(project), client: c, header: http.Header{"Private-Token": {token}}}, nil
}

func (g *gitlabAPI) url(path string, q url.Values) *url.URL {
	return apiURL(g.base, "/api/v4/projects/"+g.project+path, q)
}

func (g *gitlabAPI) list(ctx context.Context) ([]trackedIssue, error) {
	var out []trackedIssue
	page := "1"
	for n := 0; page != ""; n++ {
		if n*trackerPage >= trackerMaxIssues {
			return nil, fmt.Errorf("more than %d issues labelled %s: not acting, to avoid duplicates", trackerMaxIssues, trackerLabel)
		}
		var items []struct {
			IID         int64  `json:"iid"`
			State       string `json:"state"`
			Description string `json:"description"`
		}
		q := url.Values{"labels": {trackerLabel}, "per_page": {strconv.Itoa(trackerPage)}, "page": {page}}
		h, err := restCall(ctx, g.client, http.MethodGet, g.url("/issues", q), g.header, nil, &items)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			if group := parseGroup(it.Description); group != "" {
				out = append(out, trackedIssue{Number: it.IID, Open: it.State == "opened", Group: group})
			}
		}
		next := h.Get("X-Next-Page")
		if _, err := strconv.Atoi(next); next != "" && err != nil {
			return nil, fmt.Errorf("gitlab: invalid X-Next-Page")
		}
		page = next
	}
	return out, nil
}

func (g *gitlabAPI) create(ctx context.Context, title, body string, labels []string) (int64, error) {
	var res struct {
		IID int64 `json:"iid"`
	}
	_, err := restCall(ctx, g.client, http.MethodPost, g.url("/issues", nil), g.header,
		map[string]any{"title": title, "description": body, "labels": strings.Join(labels, ",")}, &res)
	if err == nil && res.IID <= 0 {
		err = errors.New("gitlab: the created issue has no iid")
	}
	return res.IID, err
}

func (g *gitlabAPI) comment(ctx context.Context, n int64, body string) error {
	_, err := restCall(ctx, g.client, http.MethodPost, g.url(fmt.Sprintf("/issues/%d/notes", n), nil), g.header, map[string]any{"body": body}, nil)
	return err
}

func (g *gitlabAPI) setOpen(ctx context.Context, n int64, open bool) error {
	ev := "close"
	if open {
		ev = "reopen"
	}
	_, err := restCall(ctx, g.client, http.MethodPut, g.url(fmt.Sprintf("/issues/%d", n), nil), g.header, map[string]any{"state_event": ev}, nil)
	return err
}

func (g *gitlabAPI) check(ctx context.Context) error {
	_, err := restCall(ctx, g.client, http.MethodGet, g.url("", nil), g.header, nil, nil)
	return err
}
