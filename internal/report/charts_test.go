package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/charts"
	"github.com/nocs90/shieldmon/internal/model"
)

func chartStatuses() []charts.Status {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	hostile := charts.Fixable{
		Image: "registry.test/app:1", VulnID: "CVE-2026-1001", Package: "@maintainers [click](https://evil.test) <img src=x> `x`\nline",
		Version: "1|2", FixVersions: []string{"1.2.4"}, Severity: model.SeverityHigh, KEV: true, FirstDetected: at,
	}
	return []charts.Status{
		{
			Chart: "web", Location: "https://charts.test", Version: "1.0.0", ReleasedAt: at,
			Images:     []charts.StatusImage{{Ref: "registry.test/app:1", Monitored: true, Fixable: 1}, {Ref: "registry.test/b:2"}},
			Assessment: charts.Assessment{Neglected: true, Reasons: []string{"1 finding | with <b>"}, Overdue: []charts.Fixable{hostile}},
		},
		{Chart: "api"},
	}
}

func TestChartsMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := ChartsMarkdown(&buf, chartStatuses(), time.Now()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"| web | 1.0.0 | 2026-10-01 | 2 (1) | 1 | yes: 1 finding \\| with &lt;b&gt; |", "| api | not rendered yet |", "CVE-2026-1001 (CISA KEV)"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "<img") || strings.Contains(out, "[click](") || strings.Contains(out, "\nline") {
		t.Errorf("hostile markup kept:\n%s", out)
	}
}

func TestChartIssueDraft(t *testing.T) {
	sts := chartStatuses()
	var buf bytes.Buffer
	if err := ChartIssueDraft(&buf, sts[0], time.Now()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "submit it yourself") || !strings.Contains(out, "`CVE-2026-1001` (high, on the CISA KEV catalog)") {
		t.Errorf("draft:\n%s", out)
	}
	// Outside code spans nothing hostile remains: no mention, link, HTML or extra line.
	outside := regexp.MustCompile("`[^`\n]*`").ReplaceAllString(out, "")
	for _, bad := range []string{"@maintainers", "](", "<img", "\nline"} {
		if strings.Contains(outside, bad) || strings.Contains(out, "\nline") {
			t.Errorf("%q outside a code span:\n%s", bad, out)
		}
	}
	if err := ChartIssueDraft(&buf, sts[1], time.Now()); err == nil {
		t.Error("nothing overdue, nothing to draft")
	}
}
