package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nocs90/shieldmon/internal/model"
)

func TestBuiltInProfilesAreCoherent(t *testing.T) {
	for name := range slaProfiles {
		if _, err := SLAProfile(name, nil); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	sla, err := SLAProfile("standard", map[string]int{"critical": 15, "negligible": 365})
	if err != nil || sla[model.SeverityCritical] != 15 || sla[model.SeverityNegligible] != 365 || sla[model.SeverityHigh] != 30 {
		t.Errorf("overrides apply over the profile: %v %v", sla, err)
	}
	if sla, err := SLAProfile("standard", map[string]int{"low": 0, "medium": 0}); err != nil || sla[model.SeverityLow] != 0 {
		t.Errorf("less severe findings may have no deadline: %v", err)
	}
}

func TestIncoherentPoliciesAreRejected(t *testing.T) {
	for what, c := range map[string]struct {
		profile string
		days    map[string]int
		want    string
	}{
		"unknown profile":         {"commercial", nil, "unknown profile"},
		"critical longer":         {"standard", map[string]int{"critical": 60}, "critical deadline (60 days) is longer than high (30 days)"},
		"medium longer than low":  {"standard", map[string]int{"medium": 200}, "medium deadline (200 days) is longer than low (180 days)"},
		"no critical deadline":    {"standard", map[string]int{"critical": 0}, "critical has no deadline while high has 30 days"},
		"negligible before low":   {"standard", map[string]int{"negligible": 30}, "is longer than negligible (30 days)"},
		"negative":                {"standard", map[string]int{"low": -1}, "invalid entry"},
		"ten years and a day":     {"standard", map[string]int{"low": MaxPolicyDays + 1}, "want 0 (none) to 3650"},
		"unknown severity":        {"standard", map[string]int{"urgent": 1}, "invalid entry"},
		"unknown is not settable": {"standard", map[string]int{"unknown": 1}, "invalid entry"},
	} {
		_, err := SLAProfile(c.profile, c.days)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", what, err, c.want)
		}
	}
}

func TestDecisionLimits(t *testing.T) {
	for what, c := range map[string]struct {
		vendor, operational int
		ok                  bool
	}{
		"defaults":                {30, 365, true},
		"equal":                   {90, 90, true},
		"zero":                    {0, 365, false},
		"vendor review too long":  {400, 365, false},
		"operational beyond 10 y": {30, MaxPolicyDays + 1, false},
	} {
		c0 := Default()
		c0.Decisions.VendorDependencyMaxDays, c0.Decisions.OperationalRequirementMaxDays = c.vendor, c.operational
		if err := c0.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: %v", what, err)
		}
	}
}

// TestTemplateLoads keeps 'shieldmon init' honest: the template is valid and is the default.
func TestTemplateLoads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(Template), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p, true)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := c.Policy()
	if err != nil || pol.Profile != "standard" || pol.SLADays[model.SeverityCritical] != 30 || pol.VendorDependencyMaxDays != 30 {
		t.Errorf("template policy = %+v, %v", pol, err)
	}
	if !reflect.DeepEqual(c.Gate, DefaultGate()) {
		t.Errorf("template gate = %+v, want the default %+v", c.Gate, DefaultGate())
	}
	bad := strings.Replace(Template, "  profile: standard\n", "  profile: standard\n  days: { critical: 90 }\n", 1)
	if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, true); err == nil || !strings.Contains(err.Error(), "more severe finding cannot get more time") {
		t.Errorf("an incoherent policy fails at startup: %v", err)
	}
}

func TestChartProfiles(t *testing.T) {
	load := func(charts string) (Config, error) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte(strings.Replace(Template, "charts: []\n", charts, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(p, true)
	}
	long := strings.Repeat("a", 60)
	c, err := load("charts:\n  - { name: my_chart.v2, chart: web, source: http }\n  - { name: " + long + ", chart: api, source: http }\n")
	if err != nil {
		t.Fatalf("chart names a release name cannot be: %v", err)
	}
	for i, want := range []string{"my-chart-v2", strings.Repeat("a", 53)} {
		ps := c.Charts[i].RenderProfiles()
		if len(ps) != 1 || ps[0].Name != "default" || ps[0].Release != want || ps[0].Namespace != "default" {
			t.Errorf("default profile of %s: %+v", c.Charts[i].ID(), ps)
		}
	}
	for conf, want := range map[string]string{
		"charts:\n  - { chart: web, source: http, profiles: [{ name: a }, { name: a }] }\n":                      "listed twice",
		"charts:\n  - { chart: web, source: http, profiles: [{ name: A }] }\n":                                   "lowercase",
		"charts:\n  - { chart: web, source: http, profiles: [{ name: a, release: --debug }] }\n":                 "release",
		"charts:\n  - { chart: web, source: http, profiles: [{ name: a, namespace: Prod }] }\n":                  "namespace",
		"charts:\n  - { chart: web, source: http, profiles: [{ name: a, kube_version: latest }] }\n":             "kube_version",
		"charts:\n  - { chart: web, source: http, profiles: [{ name: a, values_files: [\"-\"] }] }\n":            "file paths",
		"charts:\n  - { chart: web, source: http, profiles: [{ name: a, values_files: [" + many(40) + "] }] }\n": "values_files",
	} {
		if _, err := load(conf); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error about %s", conf, err, want)
		}
	}
}

func many(n int) string {
	files := make([]string, n)
	for i := range files {
		files[i] = "/etc/v.yaml"
	}
	return strings.Join(files, ", ")
}
