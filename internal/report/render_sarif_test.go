package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func sarifFixture() Monthly {
	r := planFixture()
	r.SLAProfile = "standard"
	r.Open = append(r.Open, Row{
		ID: 11, State: "open", VulnID: "GHSA-xxxx-yyyy-zzzz", Severity: "medium", CVSS: 5.3, Package: "@angular/core",
		Version: "1.0.0", PURL: "pkg:npm/%40angular/core@1.0.0", Targets: []string{"registry.test/web:1 (linux/amd64)"},
		Digest: "sha256:cccc", Title: "<script>alert(1)</script> {{ x }}\n```", FirstDetected: day("2026-10-10"),
	}, Row{
		ID: 12, State: "open", VulnID: "CVE-2026-0002", Severity: "low", Package: "weird pkg", Version: "1",
		PURL: "pkg:generic/weird pkg@1?x=<y>|\"z\"", Digest: "sha256:dddd", FirstDetected: day("2026-10-11"),
	})
	return r
}

func TestSARIFIsValidAndStable(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sarifFixture(), "sarif"); err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/report.golden.sarif"
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

	schemaFile, err := os.Open("testdata/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	defer schemaFile.Close()
	schema, err := jsonschema.UnmarshalJSON(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("sarif.json", schema); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("sarif.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("not valid SARIF 2.1.0: %v", err)
	}

	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string }
				}
			}
			Results []struct {
				RuleID       string
				RuleIndex    int
				Level        string
				Suppressions []struct{ Status, Justification string }
				Locations    []struct {
					PhysicalLocation struct{ ArtifactLocation struct{ URI string } }
				}
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if len(run.Results) != 6 {
		t.Fatalf("one result per open or risk-accepted finding: %d", len(run.Results))
	}
	suppressed := 0
	for _, res := range run.Results {
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("ruleIndex of %s points elsewhere", res.RuleID)
		}
		if len(res.Suppressions) > 0 {
			suppressed++
			if res.Suppressions[0].Status != "accepted" {
				t.Errorf("risk acceptance suppression: %+v", res.Suppressions)
			}
		}
		uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
		if strings.ContainsAny(uri, " <>\"|") || strings.Contains(uri, "%2540") {
			t.Errorf("artifact URI %q is not a clean URI", uri)
		}
	}
	if suppressed != 2 {
		t.Errorf("risk acceptances are suppressed results: %d", suppressed)
	}
	if strings.Contains(buf.String(), "<script>") {
		t.Error("hostile markup must be JSON-escaped")
	}
}
