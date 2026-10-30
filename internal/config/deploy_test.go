package config

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The deployment examples (deploy/, docs/processes/deployment.md) are copied as they are: they
// must load with this version and keep their hardening.

func TestKubernetesExample(t *testing.T) {
	dir := filepath.Join("..", "..", "deploy", "kubernetes")
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	readYAML(t, filepath.Join(dir, "configmap.yaml"), &cm)
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(cm.Data["config.yaml"]), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, true); err != nil {
		t.Errorf("the ConfigMap's config.yaml does not load: %v", err)
	}
	if _, ok := cm.Data["targets.txt"]; !ok {
		t.Error("targets.txt is in the ConfigMap")
	}

	type container struct {
		Name            string   `yaml:"name"`
		Args            []string `yaml:"args"`
		SecurityContext struct {
			AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
			ReadOnlyRootFilesystem   bool  `yaml:"readOnlyRootFilesystem"`
			Capabilities             struct {
				Drop []string `yaml:"drop"`
			} `yaml:"capabilities"`
		} `yaml:"securityContext"`
	}
	var cj struct {
		Spec struct {
			ConcurrencyPolicy string `yaml:"concurrencyPolicy"`
			JobTemplate       struct {
				Spec struct {
					Template struct {
						Spec struct {
							AutomountServiceAccountToken *bool `yaml:"automountServiceAccountToken"`
							SecurityContext              struct {
								RunAsNonRoot   bool `yaml:"runAsNonRoot"`
								RunAsUser      int  `yaml:"runAsUser"`
								SeccompProfile struct {
									Type string `yaml:"type"`
								} `yaml:"seccompProfile"`
							} `yaml:"securityContext"`
							InitContainers []container `yaml:"initContainers"`
							Containers     []container `yaml:"containers"`
						} `yaml:"spec"`
					} `yaml:"template"`
				} `yaml:"spec"`
			} `yaml:"jobTemplate"`
		} `yaml:"spec"`
	}
	readYAML(t, filepath.Join(dir, "cronjob.yaml"), &cj)
	pod := cj.Spec.JobTemplate.Spec.Template.Spec
	if cj.Spec.ConcurrencyPolicy != "Forbid" {
		t.Errorf("concurrencyPolicy = %q: one cycle at a time", cj.Spec.ConcurrencyPolicy)
	}
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Error("no service account token")
	}
	if sc := pod.SecurityContext; !sc.RunAsNonRoot || sc.RunAsUser != 65532 || sc.SeccompProfile.Type != "RuntimeDefault" {
		t.Errorf("pod security context: %+v", sc)
	}
	all := slices.Concat(pod.InitContainers, pod.Containers)
	if len(all) != 2 || !slices.Contains(pod.Containers[0].Args, "monitor") || !slices.Contains(pod.InitContainers[0].Args, "targets") {
		t.Fatalf("containers: %+v", all)
	}
	for _, c := range all {
		sc := c.SecurityContext
		if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || !sc.ReadOnlyRootFilesystem || !slices.Equal(sc.Capabilities.Drop, []string{"ALL"}) {
			t.Errorf("%s: container security context %+v", c.Name, sc)
		}
	}
}

func TestSystemdExample(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "shieldmon-monitor.service"))
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			set[k] = v
		}
	}
	for k, want := range map[string]string{
		"User": "shieldmon", "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes",
		"PrivateTmp": "yes", "CapabilityBoundingSet": "", "StateDirectoryMode": "0700", "UMask": "0077",
	} {
		if got, ok := set[k]; !ok || got != want {
			t.Errorf("%s=%q, want %q", k, got, want)
		}
	}
	// These would stop the bwrap sandbox from starting: the scanners would not run confined.
	for _, k := range []string{"RestrictNamespaces", "SystemCallFilter", "MemoryDenyWriteExecute"} {
		if _, ok := set[k]; ok {
			t.Errorf("%s breaks the bwrap scanner sandbox", k)
		}
	}
	if !strings.Contains(set["ExecStart"], " monitor") || !strings.Contains(set["ExecStartPre"], "targets add -f") {
		t.Errorf("ExecStart %q, ExecStartPre %q", set["ExecStart"], set["ExecStartPre"])
	}
}

func readYAML(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}
