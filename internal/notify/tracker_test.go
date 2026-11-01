package notify_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/notify"
	"github.com/nocs90/shieldmon/internal/notify/notifytest"
)

const trackerToken = "ghp_trackertoken0123456789abcdefghij"

type fakeIssue struct {
	Number   int64
	Title    string
	Body     string
	Labels   []string
	Open     bool
	Comments []string
	PR       bool
}

// fakeTracker is an in-memory GitHub (flavor "github") or GitLab ("gitlab") issues API that
// requires the token and records the bodies of writes.
type fakeTracker struct {
	flavor string
	srv    *httptest.Server
	mu     sync.Mutex
	issues []*fakeIssue
	writes []string
	reqs   []string
}

func newFakeTracker(t *testing.T, flavor string) *fakeTracker {
	t.Helper()
	f := &fakeTracker{flavor: flavor}
	issuePath := regexp.MustCompile(`^/(?:repos/acme/app|api/v4/projects/acme%2Fplatform%2Fapp)/issues(?:/(\d+)(/comments|/notes)?)?$`)
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.reqs = append(f.reqs, r.Method+" "+r.URL.EscapedPath())
		authorized := r.Header.Get("Authorization") == "Bearer "+trackerToken
		if flavor == "gitlab" {
			authorized = r.Header.Get("Private-Token") == trackerToken
		}
		if !authorized {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodGet {
			f.writes = append(f.writes, string(body))
		}
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		path := r.URL.EscapedPath()
		if path == "/repos/acme/app" || path == "/api/v4/projects/acme%2Fplatform%2Fapp" {
			_, _ = io.WriteString(w, `{"id":1}`)
			return
		}
		m := issuePath.FindStringSubmatch(path)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		switch {
		case m[1] == "" && r.Method == http.MethodGet:
			f.list(w, r)
		case m[1] == "" && r.Method == http.MethodPost:
			is := &fakeIssue{Number: int64(len(f.issues) + 1), Title: in["title"].(string), Open: true}
			if flavor == "gitlab" {
				is.Body, is.Labels = in["description"].(string), strings.Split(in["labels"].(string), ",")
			} else {
				is.Body = in["body"].(string)
				for _, l := range in["labels"].([]any) {
					is.Labels = append(is.Labels, l.(string))
				}
			}
			f.issues = append(f.issues, is)
			fmt.Fprintf(w, `{"number":%d,"iid":%d}`, is.Number, is.Number)
		default:
			n, _ := strconv.Atoi(m[1])
			if n < 1 || n > len(f.issues) {
				http.NotFound(w, r)
				return
			}
			is := f.issues[n-1]
			switch {
			case m[2] != "":
				is.Comments = append(is.Comments, in["body"].(string))
			case flavor == "gitlab":
				is.Open = in["state_event"] == "reopen"
			default:
				is.Open = in["state"] == "open"
			}
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// list pages by 100 like both APIs; GitLab says where the next page is.
func (f *fakeTracker) list(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	var labelled []map[string]any
	for _, is := range f.issues {
		if !strings.Contains(strings.Join(is.Labels, ","), "shieldmon") {
			continue
		}
		state := map[bool]string{true: "open", false: "closed"}[is.Open]
		item := map[string]any{"number": is.Number, "iid": is.Number, "state": state, "body": is.Body}
		if f.flavor == "gitlab" {
			item = map[string]any{"iid": is.Number, "state": map[bool]string{true: "opened", false: "closed"}[is.Open], "description": is.Body}
		}
		if is.PR {
			item["pull_request"] = map[string]any{}
		}
		labelled = append(labelled, item)
	}
	start, end := (page-1)*100, min(page*100, len(labelled))
	if start > len(labelled) {
		start = end
	}
	if f.flavor == "gitlab" && end < len(labelled) {
		w.Header().Set("X-Next-Page", strconv.Itoa(page+1))
	}
	_ = json.NewEncoder(w).Encode(append([]map[string]any{}, labelled[start:end]...))
}

func (f *fakeTracker) Writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

func trackerOptions(flavor, base string) map[string]any {
	if flavor == "gitlab" {
		return map[string]any{"project": "acme/platform/app", "api_url": base, "token_env": "TRACKER_TOKEN", "labels": []any{"security"}}
	}
	return map[string]any{"repo": "acme/app", "api_url": base, "token_env": "TRACKER_TOKEN", "labels": []any{"security"}}
}

func trackerChannel(t *testing.T, flavor, base string, transport http.RoundTripper) notify.Channel {
	t.Helper()
	chs, err := notify.NewChannels([]notify.ChannelConfig{{Name: "issues", Notifier: flavor + "-issues", Options: trackerOptions(flavor, base)}},
		notify.Spec{Transport: transport, Env: func(k string) string {
			if k == "TRACKER_TOKEN" {
				return trackerToken
			}
			return ""
		}})
	if err != nil {
		t.Fatal(err)
	}
	return chs[0]
}

func TestTrackerConformance(t *testing.T) {
	for _, flavor := range []string{"github", "gitlab"} {
		t.Run(flavor, func(t *testing.T) {
			api := newFakeTracker(t, flavor)
			mk := func(r *notifytest.Receiver) notify.Notifier {
				return trackerChannel(t, flavor, r.URL, r.Client.Transport).Sender
			}
			redirect := notifytest.NewReceiver(t, notifytest.Redirect)
			notifytest.CheckNotifier(t, notifytest.Fixture{
				Name:        flavor + "-issues",
				Notifier:    trackerChannel(t, flavor, api.srv.URL, api.srv.Client().Transport).Sender,
				Received:    api.Writes,
				Failing:     mk(notifytest.NewReceiver(t, notifytest.Reject)),
				Hanging:     mk(notifytest.NewReceiver(t, notifytest.Hang)),
				Redirecting: mk(redirect),
				Followed:    redirect.Followed,
				Secret:      trackerToken,
			})
		})
	}
}

func finding(id int64, vuln string, targets ...string) *notify.Finding {
	return &notify.Finding{
		ID: id, Lineage: id, VulnID: vuln, Package: "openssl", Version: "3.0.1", Severity: "critical",
		Digest: "sha256:aaaa", Targets: targets, State: "open", FirstDetected: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestTrackerFollowsProblems: one issue per target and vulnerability, commented not
// duplicated, closed only when the vulnerability is gone, reopened when it comes back.
func TestTrackerFollowsProblems(t *testing.T) {
	for _, flavor := range []string{"github", "gitlab"} {
		t.Run(flavor, func(t *testing.T) {
			const prod, staging = "registry.test/app:prod (linux/amd64)", "registry.test/app:staging (linux/amd64)"
			prodGroup, stagingGroup := group(prod, "CVE-2024-0001"), group(staging, "CVE-2024-0001")
			api := newFakeTracker(t, flavor)
			// Issues ShieldMon must leave alone although they look like prod's: made by hand, a
			// pull request, a marker that is not on the first line (as hostile text could hold it).
			api.issues = append(api.issues,
				&fakeIssue{Number: 1, Title: "hand-made", Body: "please fix " + prodGroup, Labels: []string{"shieldmon"}, Open: true},
				&fakeIssue{Number: 2, Title: "PR", Body: marker(prodGroup), Labels: []string{"shieldmon"}, Open: true, PR: flavor == "github"},
				&fakeIssue{Number: 3, Title: "forged", Body: "x\n" + marker(prodGroup), Labels: []string{"shieldmon"}, Open: true},
			)
			if flavor == "gitlab" {
				api.issues[1].Body = "x\n" + marker(prodGroup) // GitLab lists no pull requests
			}
			// Enough managed issues to need a second page, staging's (closed) on it.
			for i := range 120 {
				api.issues = append(api.issues, &fakeIssue{Number: int64(len(api.issues) + 1), Body: marker(fmt.Sprintf("%020x", i+1)), Labels: []string{"shieldmon"}})
			}
			stagingIssue := &fakeIssue{Number: int64(len(api.issues) + 1), Title: "staging", Body: marker(stagingGroup), Labels: []string{"shieldmon"}}
			api.issues = append(api.issues, stagingIssue)
			n := trackerChannel(t, flavor, api.srv.URL, api.srv.Client().Transport).Sender
			at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
			send := func(e notify.Event) {
				t.Helper()
				at = at.Add(time.Hour) // a new cycle each time: the listing is read again
				if err := n.Send(context.Background(), notify.Message{Channel: "issues", Events: []notify.Event{e}, SentAt: at}); err != nil {
					t.Fatal(err)
				}
			}
			base := len(api.issues)

			send(notify.Event{Key: "finding_new:10", Kind: notify.FindingNewKEV, Finding: finding(10, "CVE-2024-0001", prod, staging)})
			if len(api.issues) != base+1 || !stagingIssue.Open || len(stagingIssue.Comments) != 1 {
				t.Fatalf("one issue per target, found on any page: %d new, staging %+v", len(api.issues)-base, stagingIssue)
			}
			first := api.issues[base]
			if !strings.HasPrefix(first.Body, "<!-- shieldmon:group=") || first.Title != "[ShieldMon] CVE-2024-0001 in "+prod ||
				strings.Join(first.Labels, ",") != "shieldmon,security" || !first.Open {
				t.Fatalf("issue %+v", first)
			}

			send(notify.Event{Key: "sla_due_soon:10", Kind: notify.SLADueSoon, Finding: finding(11, "CVE-2024-0001", prod)})
			send(notify.Event{Key: "finding_new:12", Kind: notify.FindingNewCritical, Finding: finding(12, "CVE-2024-0001", prod)})
			if len(api.issues) != base+1 || len(first.Comments) != 2 {
				t.Fatalf("the same problem is commented, not duplicated: %d issues, %d comments", len(api.issues)-base, len(first.Comments))
			}

			fixed := notify.Event{Key: "finding_fixed:11", Kind: notify.FindingFixed, Finding: finding(11, "CVE-2024-0001", prod), Remaining: 1}
			send(fixed)
			if !first.Open || len(first.Comments) != 3 {
				t.Fatal("fixed in one package while another still has it: comment, keep open")
			}
			fixed.Key, fixed.Remaining = "finding_fixed:12", 0
			send(fixed)
			if first.Open || !stagingIssue.Open {
				t.Fatal("the issue closes when the vulnerability is gone from its target, and only that one")
			}

			send(notify.Event{Key: "finding_new:20", Kind: notify.FindingNewCritical, Finding: finding(20, "CVE-2024-0001", prod)})
			if !first.Open || !strings.Contains(first.Comments[len(first.Comments)-1], "Reopened by ShieldMon") || len(api.issues) != base+1 {
				t.Fatal("a problem that comes back reopens its issue")
			}
			for _, is := range api.issues[:3] {
				if len(is.Comments) != 0 || !is.Open {
					t.Errorf("issue %q was touched", is.Title)
				}
			}

			// A fix for a problem without an issue does nothing; a test message only reads.
			writes := len(api.Writes())
			send(notify.Event{Key: "finding_fixed:30", Kind: notify.FindingFixed, Finding: finding(30, "CVE-2024-9999", prod)})
			if err := n.Send(context.Background(), notify.Message{Channel: "issues", Test: true, SentAt: at}); err != nil {
				t.Fatal(err)
			}
			if len(api.Writes()) != writes {
				t.Error("nothing is written for a fix without an issue, or for a test message")
			}
		})
	}
}

func TestTrackerRefusesWeakConfiguration(t *testing.T) {
	env := notify.Spec{Env: func(string) string { return "token-value" }}
	for what, c := range map[string]notify.ChannelConfig{
		"digest":           {Notifier: "github-issues", Digest: true, Options: map[string]any{"repo": "a/b", "token_env": "T"}},
		"health events":    {Notifier: "github-issues", Events: []string{"health_opened"}, Options: map[string]any{"repo": "a/b", "token_env": "T"}},
		"no token":         {Notifier: "github-issues", Options: map[string]any{"repo": "a/b"}},
		"repo traversal":   {Notifier: "github-issues", Options: map[string]any{"repo": "a/../b", "token_env": "T"}},
		"repo URL":         {Notifier: "github-issues", Options: map[string]any{"repo": "https://github.com/a/b", "token_env": "T"}},
		"project slash":    {Notifier: "gitlab-issues", Options: map[string]any{"project": "/a/b", "token_env": "T"}},
		"label with comma": {Notifier: "gitlab-issues", Options: map[string]any{"project": "a/b", "token_env": "T", "labels": []any{"x,y"}}},
		"http API":         {Notifier: "gitlab-issues", Options: map[string]any{"project": "a/b", "token_env": "T", "api_url": "http://gitlab.example.com"}},
	} {
		c.Name = "t"
		if _, err := notify.NewChannels([]notify.ChannelConfig{c}, env); err == nil {
			t.Errorf("%s: must be refused", what)
		}
	}
	chs, err := notify.NewChannels([]notify.ChannelConfig{{Name: "t", Notifier: "gitlab-issues", Options: map[string]any{"project": "1234", "token_env": "T"}}}, env)
	if err != nil || len(chs[0].Kinds) != 5 || !chs[0].Wants(notify.FindingFixed) || chs[0].Wants(notify.HealthOpened) {
		t.Errorf("a tracker channel defaults to the finding events, fixes included: %v %+v", err, chs)
	}
}

func marker(group string) string { return "<!-- shieldmon:group=" + group + " -->" }

// group is the tracker's group key, recomputed: sha256(target NUL vulnerability), 10 bytes.
func group(target, vuln string) string {
	sum := sha256.Sum256([]byte(target + "\x00" + vuln))
	return hex.EncodeToString(sum[:10])
}
