package oci_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// iamDir holds the shipped policies (deploy/iam/README.md).
const iamDir = "../../deploy/iam"

type policy struct {
	Statement []struct {
		Effect    string
		Action    any
		Principal any
		Condition map[string]map[string]any
	}
}

func readPolicy(t *testing.T, file string) policy {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(iamDir, file))
	if err != nil {
		t.Fatal(err)
	}
	var p policy
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return p
}

func strs(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, s := range v {
			out = append(out, s.(string))
		}
		return out
	}
	return nil
}

// TestReadOnlyPolicyGrantsExactlyWhatShieldMonCalls is S2's least-privilege check: adding an
// ECR call to the provider means adding it here and to the policy, in review.
func TestReadOnlyPolicyGrantsExactlyWhatShieldMonCalls(t *testing.T) {
	want := []string{
		"ecr:BatchGetImage",          // manifests (registry v2 API)
		"ecr:DescribeImages",         // ecrProvider.Tags
		"ecr:DescribeRepositories",   // ecrProvider.Repositories
		"ecr:GetAuthorizationToken",  // ecrProvider.Resolve
		"ecr:GetDownloadUrlForLayer", // layers (registry v2 API)
	}
	var got []string
	for _, s := range readPolicy(t, "shieldmon-readonly.json").Statement {
		if s.Effect != "Allow" {
			t.Errorf("unexpected %s statement", s.Effect)
		}
		got = append(got, strs(s.Action)...)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("policy actions = %v, want exactly %v", got, want)
	}
}

// TestTrustPoliciesArePinned keeps the examples from trusting more than one identity.
func TestTrustPoliciesArePinned(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(iamDir, "trust-*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no trust policies: %v", err)
	}
	for _, f := range files {
		for _, s := range readPolicy(t, filepath.Base(f)).Statement {
			principal, _ := s.Principal.(map[string]any)
			if s.Principal == "*" || principal == nil {
				t.Errorf("%s: the principal must be one identity, not %v", f, s.Principal)
				continue
			}
			eq := s.Condition["StringEquals"]
			has := func(suffix string) bool {
				for k := range eq {
					if strings.HasSuffix(k, suffix) {
						return true
					}
				}
				return false
			}
			switch {
			case principal["Federated"] != nil:
				if !has(":aud") || !has(":sub") {
					t.Errorf("%s: a federated principal must be pinned by aud and sub", f)
				}
			case principal["Service"] != nil:
				if !has("aws:SourceAccount") {
					t.Errorf("%s: a service principal must be pinned to the account", f)
				}
			case principal["AWS"] != nil:
				if !has("sts:ExternalId") {
					t.Errorf("%s: another account's role must present an external ID", f)
				}
			}
		}
	}
}
