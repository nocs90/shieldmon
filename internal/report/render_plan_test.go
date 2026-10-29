package report

import (
	"bytes"
	"encoding/csv"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

func day(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return t
}

// planFixture has an overdue item with a fix, a vendor dependency, a plain risk acceptance
// and hostile strings in every free-text field.
func planFixture() Monthly {
	return Monthly{
		Period: MonthPeriod(day("2026-10-01")),
		Open: []Row{
			{
				ID: 7, Priority: 60, State: "open", VulnID: "CVE-2024-6119", Severity: "high", CVSS: 7.5, EPSS: 0.01234, Package: "libcrypto3",
				Version: "3.3.1-r0", PURL: "pkg:apk/alpine/libcrypto3@3.3.1-r0", FixVersions: []string{"3.3.2-r0"}, FixState: "fixed",
				Title: "openssl: possible denial of service\nin X.509 name checks", Targets: []string{"registry.test/app:prod (linux/amd64)"},
				Digest: "sha256:aaaa", FirstDetected: day("2026-09-01"), AgeDays: 58, SLADue: day("2026-10-01"), SLABreached: true,
			},
			{
				ID: 9, Priority: 46, State: "triaged", VulnID: "CVE-2026-0001", Severity: "critical", Package: `=HYPERLINK("http://evil","x")`,
				Version: "1.0", PURL: "pkg:npm/evil@1.0", FixState: "not_fixed", Targets: []string{"registry.test/app:prod (linux/amd64)"},
				Digest: "sha256:aaaa", FirstDetected: day("2026-10-20"), AgeDays: 8, SLADue: day("2026-11-19"),
			},
		},
		AcceptedRisks: []Row{
			{
				ID: 3, State: "risk_accepted", VulnID: "CVE-2023-45853", Aliases: []string{"GHSA-mq29-j5xf-cjwr"}, Severity: "critical",
				Package: "zlib", Version: "1.2.13-r0", FixState: "wont_fix", Digest: "sha256:bbbb", FirstDetected: day("2026-09-20"),
				AgeDays: 38, SLADue: day("2026-10-20"), SLABreached: true,
				Decision: &DecisionInfo{
					State: "risk_accepted", Deviation: "vendor_dependency", Author: "secops-lead",
					Justification: "+vendor will not fix; minizip not built", ExpiresAt: day("2026-11-15"),
				},
			},
			{
				ID: 4, State: "risk_accepted", VulnID: "CVE-2022-48174", Severity: "low", Package: "busybox", Version: "1.36.0",
				Digest: "sha256:bbbb", FirstDetected: day("2026-10-02"), AgeDays: 26, SLADue: day("2027-03-31"),
				Decision: &DecisionInfo{State: "risk_accepted", Author: "@team", Justification: "shell not reachable", ExpiresAt: day("2026-12-01")},
			},
			// Not affected is no weakness: in neither the plan nor SARIF (docs/processes/reporting.md).
			{
				ID: 13, State: "not_affected", VulnID: "CVE-2026-0003", Severity: "critical", Package: "zlib", Version: "1.3",
				PURL: "pkg:apk/alpine/zlib@1.3", Digest: "sha256:eeee", FirstDetected: day("2026-09-12"), AgeDays: 46,
				SLADue: day("2026-10-12"), SLABreached: true,
				Decision: &DecisionInfo{State: "not_affected", Author: "vendor", Justification: "vulnerable_code_not_present"},
			},
		},
	}
}

func TestRemediationPlanGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, planFixture(), "remediation-plan"); err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/remediation-plan.golden.csv"
	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/report -update)", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("output differs from %s:\n%s", golden, buf.String())
	}

	recs, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 5 {
		t.Fatalf("one row per open or risk-accepted item: %d", len(recs)-1)
	}
	for _, rec := range recs[1:] {
		for _, v := range rec {
			if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
				t.Errorf("unsafe cell %q", v)
			}
			if strings.ContainsAny(v, "\r\n") {
				t.Errorf("cell spans lines: %q", v)
			}
		}
	}
	// Soonest scheduled completion first: the breached item, the vendor review, the critical
	// one, the low-severity acceptance.
	var order []string
	for _, rec := range recs[1:] {
		order = append(order, rec[0])
	}
	if strings.Join(order, ",") != "7,3,9,4" {
		t.Errorf("order = %v", order)
	}
}

func TestRemediationPlanExcel(t *testing.T) {
	var plain, excel bytes.Buffer
	if err := Render(&plain, planFixture(), "remediation-plan"); err != nil {
		t.Fatal(err)
	}
	if err := Render(&excel, planFixture(), "remediation-plan-excel"); err != nil {
		t.Fatal(err)
	}
	got := excel.String()
	if !strings.HasPrefix(got, "\uFEFFitem_id,") || strings.Count(got, "\r\n") != 5 {
		t.Fatalf("UTF-8 BOM and CRLF line endings expected: %q", got[:40])
	}
	if strings.ReplaceAll(strings.TrimPrefix(got, "\uFEFF"), "\r\n", "\n") != plain.String() {
		t.Error("same content as remediation-plan")
	}
}
