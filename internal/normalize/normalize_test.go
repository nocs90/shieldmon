package normalize

import (
	"slices"
	"testing"

	"github.com/nocs90/shieldmon/internal/model"
)

func TestCanonicalPURL(t *testing.T) {
	tests := []struct {
		name, raw, wantPURL, wantKey string
	}{
		{
			name:     "syft apk drops arch, distro and package-id",
			raw:      "pkg:apk/alpine/busybox@1.36.0-r9?arch=aarch64&distro=alpine-3.18.0&package-id=0cb283ffa14646ee",
			wantPURL: "pkg:apk/alpine/busybox@1.36.0-r9",
			wantKey:  "pkg:apk/alpine/busybox",
		},
		{
			name:     "trivy apk is identical after canonicalization",
			raw:      "pkg:apk/alpine/busybox@1.36.0-r9?arch=aarch64&distro=3.18.0",
			wantPURL: "pkg:apk/alpine/busybox@1.36.0-r9",
			wantKey:  "pkg:apk/alpine/busybox",
		},
		{
			name:     "rpm keeps epoch",
			raw:      "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6?arch=x86_64&epoch=1&distro=rhel-8.6",
			wantPURL: "pkg:rpm/redhat/openssl@1.1.1k-7.el8_6?epoch=1",
			wantKey:  "pkg:rpm/redhat/openssl?epoch=1",
		},
		{
			name:     "pypi name normalization",
			raw:      "pkg:pypi/Django_Rest@3.14.0",
			wantPURL: "pkg:pypi/django-rest@3.14.0",
			wantKey:  "pkg:pypi/django-rest",
		},
		{
			name:     "subpath dropped",
			raw:      "pkg:golang/github.com/foo/bar@v1.2.3#cmd/x",
			wantPURL: "pkg:golang/github.com/foo/bar@v1.2.3",
			wantKey:  "pkg:golang/github.com/foo/bar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPURL, gotKey := CanonicalPURL(tt.raw, "", "", "")
			if gotPURL != tt.wantPURL || gotKey != tt.wantKey {
				t.Errorf("got (%s, %s), want (%s, %s)", gotPURL, gotKey, tt.wantPURL, tt.wantKey)
			}
		})
	}
}

func TestCanonicalPURLFallback(t *testing.T) {
	purl, key := CanonicalPURL("not a purl", "binary", "node", "20.1.0")
	if purl != "pkg:binary/node@20.1.0" || key != "pkg:binary/node" {
		t.Errorf("fallback = (%s, %s)", purl, key)
	}
}

func TestCanonicalVulnID(t *testing.T) {
	for in, want := range map[string]string{
		"cve-2024-1234":       "CVE-2024-1234",
		" CVE-2024-1234 ":     "CVE-2024-1234",
		"ghsa-ABCD-efgh-1234": "GHSA-abcd-efgh-1234",
		"GHSA-abcd-efgh-1234": "GHSA-abcd-efgh-1234",
		"ALPINE-CVE-2024-1":   "ALPINE-CVE-2024-1",
		"DLA-3456-1":          "DLA-3456-1",
	} {
		if got := CanonicalVulnID(in); got != want {
			t.Errorf("CanonicalVulnID(%q) = %q, want %q", in, got, want)
		}
	}
}

const busybox = "pkg:apk/alpine/busybox@1.36.0-r9?arch=x86_64&distro=alpine-3.18.0"

func TestMergeDeduplicatesAcrossScanners(t *testing.T) {
	got := Merge([]model.RawMatch{
		{
			Scanner: "grype", VulnID: "CVE-2022-48174", PURL: busybox, PkgName: "busybox", PkgVersion: "1.36.0-r9",
			Severity: model.SeverityHigh, CVSSScore: 9.8, FixVersions: []string{"1.36.1-r1"}, EPSS: 0.1,
		},
		{
			Scanner: "trivy", VulnID: "cve-2022-48174", PURL: busybox + "&package-id=x", PkgName: "busybox", PkgVersion: "1.36.0-r9",
			Severity: model.SeverityCritical, CVSSScore: 9.8, FixVersions: []string{"1.36.1-r1"}, KEV: true, Title: "stack overflow",
		},
	})
	if len(got) != 1 {
		t.Fatalf("want 1 merged match, got %d: %+v", len(got), got)
	}
	m := got[0]
	if m.Severity != model.SeverityCritical {
		t.Errorf("severity = %s, want highest (critical)", m.Severity)
	}
	if !slices.Equal(m.Scanners, []string{"grype", "trivy"}) {
		t.Errorf("scanners = %v", m.Scanners)
	}
	if !slices.Equal(m.FixVersions, []string{"1.36.1-r1"}) {
		t.Errorf("fix versions = %v", m.FixVersions)
	}
	if !m.KEV || m.EPSS != 0.1 || m.Title != "stack overflow" {
		t.Errorf("metadata not merged: %+v", m)
	}
}

func TestMergeMapsGHSAToSingleCVE(t *testing.T) {
	purl := "pkg:npm/lodash@4.17.20"
	got := Merge([]model.RawMatch{
		{Scanner: "grype", VulnID: "GHSA-35jh-r3h4-6jhm", Aliases: []string{"CVE-2021-23337"}, PURL: purl, Severity: model.SeverityHigh},
		{Scanner: "trivy", VulnID: "CVE-2021-23337", PURL: purl, Severity: model.SeverityHigh},
	})
	if len(got) != 1 {
		t.Fatalf("want 1 match, got %d: %+v", len(got), got)
	}
	if got[0].VulnID != "CVE-2021-23337" || !slices.Equal(got[0].Aliases, []string{"GHSA-35jh-r3h4-6jhm"}) {
		t.Errorf("got %s aliases %v", got[0].VulnID, got[0].Aliases)
	}
}

func TestMergeKeepsMultiCVEAdvisoryDistinct(t *testing.T) {
	purl := "pkg:deb/debian/openssl@3.0.11-1"
	got := Merge([]model.RawMatch{
		{Scanner: "grype", VulnID: "DSA-5532-1", Aliases: []string{"CVE-2023-5363", "CVE-2023-5678"}, PURL: purl},
		{Scanner: "trivy", VulnID: "CVE-2023-5363", PURL: purl},
	})
	ids := []string{}
	for _, m := range got {
		ids = append(ids, m.VulnID)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"CVE-2023-5363", "DSA-5532-1"}) {
		t.Errorf("advisory covering two CVEs must not be collapsed, got %v", ids)
	}
}

func TestMergeSeparatesPackages(t *testing.T) {
	got := Merge([]model.RawMatch{
		{Scanner: "grype", VulnID: "CVE-1", PURL: "pkg:apk/alpine/libssl3@3.1.0-r4"},
		{Scanner: "grype", VulnID: "CVE-1", PURL: "pkg:apk/alpine/libcrypto3@3.1.0-r4"},
	})
	if len(got) != 2 {
		t.Fatalf("same CVE in two packages must stay two findings, got %d", len(got))
	}
	if got[0].LineageKey() == got[1].LineageKey() {
		t.Error("lineage keys must differ per package")
	}
}
