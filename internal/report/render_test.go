package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func TestCSVNeutralizesFormulaInjection(t *testing.T) {
	r := Monthly{Open: []Row{{ID: 1, Package: "=HYPERLINK(\"http://evil\")", Version: "-1+1", VulnID: "@SUM(A1)", Severity: "high"}}}
	var buf bytes.Buffer
	if err := Render(&buf, r, "csv"); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range recs[1] {
		if v != "" && strings.ContainsRune("=+-@", rune(v[0])) {
			t.Errorf("unsafe cell %q", v)
		}
	}
}

func TestMarkdownEscapesHostileStrings(t *testing.T) {
	r := Monthly{
		Period: MonthPeriod(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)),
		Open:   []Row{{ID: 1, Package: "evil|pkg<script>", VulnID: "CVE-1](http://x)", Severity: "high"}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, r, "md"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>") || strings.Contains(out, "evil|pkg") || strings.Contains(out, "CVE-1](") {
		t.Errorf("hostile content not escaped:\n%s", out)
	}
	if !strings.Contains(out, "October 2026") {
		t.Error("missing period title")
	}
}

func TestMeanMedian(t *testing.T) {
	if m, md := meanMedian([]float64{1, 2, 3, 10}); m != 4 || md != 2.5 {
		t.Errorf("got %v %v", m, md)
	}
	if m, md := meanMedian(nil); m != 0 || md != 0 {
		t.Errorf("empty: %v %v", m, md)
	}
}

func TestHTMLIsSelfContainedAndEscaped(t *testing.T) {
	r := Monthly{
		Period:         MonthPeriod(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)),
		SLAProfile:     "standard",
		OpenBySeverity: map[string]int{"high": 1},
		Aging:          map[string]int{"0-30": 1},
		Burndown:       []DayCount{{Day: "2026-10-01", Open: 0}, {Day: "2026-10-02", Open: 1}},
		Summary:        Summary{OpenAtEnd: 1},
		Open: []Row{{
			ID: 1, Package: `evil"><script>alert(1)</script>`, VulnID: `CVE-1"onmouseover="x`, Severity: "high",
			Title: "<img src=x onerror=alert(1)>", FixState: "wont_fix",
		}},
		AcceptedRisks: []Row{{ID: 2, VulnID: "CVE-2", Severity: "low", Decision: &DecisionInfo{
			State: "risk_accepted", Deviation: "vendor_dependency", Author: "a", Justification: "<b>no fix</b>",
		}}},
	}
	var buf bytes.Buffer
	if err := Render(&buf, r, "html"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, bad := range []string{"<script>", "<img src=x", "<b>no fix</b>", `"onmouseover="`, "{{", "<link", "<script src", "@import"} {
		if strings.Contains(out, bad) {
			t.Errorf("HTML contains %q", bad)
		}
	}
	for _, want := range []string{"October 2026", "Content-Security-Policy", "won&#39;t fix", "Vendor dependency", "<svg", "standard"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
	if len(out) > 200_000 {
		t.Errorf("HTML unexpectedly large: %d bytes", len(out))
	}
}
