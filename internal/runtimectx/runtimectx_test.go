package runtimectx

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	web   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	api   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	batch = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	agent = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	gone  = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	debug = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
)

var taken = time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)

// list is shaped like `kubectl get pods,services,ingresses,httproutes -A -o json`.
const list = `{"apiVersion":"v1","kind":"List","items":[
 {"apiVersion":"v1","kind":"Pod","metadata":{"name":"web-1","namespace":"shop","labels":{"app":"web","tier":"fe"}},
  "spec":{"containers":[{"name":"web"},{"name":"proxy"}]},
  "status":{"phase":"Running","containerStatuses":[
    {"name":"web","imageID":"docker.io/acme/web@` + web + `","state":{"running":{"startedAt":"2026-10-31T00:00:00Z"}}},
    {"name":"proxy","imageID":"docker-pullable://envoy@` + api + `","state":{"waiting":{"reason":"CrashLoopBackOff"}}}],
   "ephemeralContainerStatuses":[{"name":"dbg","imageID":"` + debug + `","state":{"running":{}}}]}},
 {"apiVersion":"v1","kind":"Pod","metadata":{"name":"web-2","namespace":"shop","labels":{"app":"web"}},
  "spec":{"containers":[{"name":"web"}]},
  "status":{"phase":"Running","containerStatuses":[{"name":"web","imageID":"docker.io/acme/web@` + web + `","state":{"running":{}}}]}},
 {"apiVersion":"v1","kind":"Pod","metadata":{"name":"api-1","namespace":"shop","labels":{"app":"api"}},
  "spec":{"containers":[{"name":"api"}]},
  "status":{"phase":"Running","containerStatuses":[{"name":"api","imageID":"ghcr.io/acme/api@` + api + `","state":{"running":{}}}]}},
 {"apiVersion":"v1","kind":"Pod","metadata":{"name":"job-1","namespace":"ops","labels":{"app":"web"}},
  "spec":{"containers":[{"name":"job"}]},
  "status":{"phase":"Running","containerStatuses":[{"name":"job","imageID":"acme/batch@` + batch + `","state":{"running":{}}}]}},
 {"apiVersion":"v1","kind":"Pod","metadata":{"name":"node-agent-x","namespace":"kube-system"},
  "spec":{"hostNetwork":true,"containers":[{"name":"agent","ports":[{"containerPort":9100}]}]},
  "status":{"phase":"Running","containerStatuses":[{"name":"agent","imageID":"quay.io/acme/agent@` + agent + `","state":{"running":{}}}]}},
 {"apiVersion":"v1","kind":"Pod","metadata":{"name":"old","namespace":"shop","labels":{"app":"web"}},
  "status":{"phase":"Succeeded","containerStatuses":[{"imageID":"acme/old@` + gone + `","state":{"terminated":{}}}]}},
 {"apiVersion":"v1","kind":"Service","metadata":{"name":"web","namespace":"shop"},"spec":{"type":"ClusterIP","selector":{"app":"web"}}},
 {"apiVersion":"v1","kind":"Service","metadata":{"name":"api-lb","namespace":"shop"},"spec":{"type":"LoadBalancer","selector":{"app":"api"}}},
 {"apiVersion":"v1","kind":"Service","metadata":{"name":"manual","namespace":"ops"},"spec":{"type":"NodePort"}},
 {"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"shop","namespace":"shop"},
  "spec":{"rules":[{"host":"shop.example","http":{"paths":[{"path":"/","backend":{"service":{"name":"web","port":{"number":80}}}}]}}]}},
 {"apiVersion":"gateway.networking.k8s.io/v1","kind":"HTTPRoute","metadata":{"name":"r","namespace":"edge"},
  "spec":{"rules":[{"backendRefs":[{"name":"missing","namespace":"shop"}]}]}}
]}`

func TestParseFindsRunningAndExposedImages(t *testing.T) {
	inv, err := Parse([]byte(list), "prod", taken)
	if err != nil {
		t.Fatal(err)
	}
	set := Set{inv}
	w := set.Lookup(web)
	if !w.Running || w.Pods != 2 || !w.Exposed || !slices.Equal(w.Exposure, []string{"prod: Ingress shop/shop → Service shop/web"}) {
		t.Errorf("web, behind an Ingress: %+v", w)
	}
	a := set.Lookup(api)
	if !a.Running || a.Pods != 1 || !slices.Equal(a.Exposure, []string{"prod: Service shop/api-lb (LoadBalancer)"}) {
		t.Errorf("api, a waiting sidecar does not count: %+v", a)
	}
	if b := set.Lookup(batch); !b.Running || b.Exposed {
		t.Errorf("a Service selects pods of its namespace only, and an empty selector none: %+v", b)
	}
	if g := set.Lookup(agent); !g.Exposed || !strings.Contains(g.Exposure[0], "hostNetwork") {
		t.Errorf("hostNetwork pod: %+v", g)
	}
	if d := set.Lookup(debug); !d.Running || !d.Exposed {
		t.Errorf("an ephemeral container shares the pod's exposure: %+v", d)
	}
	if o := set.Lookup(gone); o.Running {
		t.Errorf("a finished pod is not running: %+v", o)
	}
	if inv.Images() != 5 {
		t.Errorf("images = %d", inv.Images())
	}
}

func TestLookupMergesClustersAndDigests(t *testing.T) {
	prod, err := Parse([]byte(list), "prod", taken)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := Parse([]byte(`{"kind":"PodList","items":[{"metadata":{"name":"w","namespace":"x"},
		"status":{"phase":"Running","containerStatuses":[{"imageID":"`+web+`","state":{"running":{}}}]}}]}`), "stage", taken)
	if err != nil {
		t.Fatal(err)
	}
	c := Set{prod, stage}.Lookup(gone, web, "")
	if c.Pods != 3 || !c.Exposed || len(c.Exposure) != 1 {
		t.Errorf("merged: %+v (items of a PodList are pods)", c)
	}
	if c := (Set{}).Lookup(web); c.Running {
		t.Errorf("no inventory, no context: %+v", c)
	}
}

func TestParseRefusesHostileInput(t *testing.T) {
	for what, in := range map[string]string{
		"not a list":   `{"kind":"Pod","metadata":{}}`,
		"not json":     `<html>`,
		"wrong types":  `{"kind":"List","items":[{"kind":"Pod","status":{"phase":7}}]}`,
		"service spec": `{"kind":"List","items":[{"kind":"Service","spec":{"selector":"all"}}]}`,
	} {
		if _, err := Parse([]byte(in), "c", taken); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
	if _, err := Parse(make([]byte, MaxBytes+1), "c", taken); err == nil {
		t.Error("oversized inventory accepted")
	}
	long := strings.Repeat("n", 500)
	inv, err := Parse([]byte(`{"kind":"List","items":[
		{"kind":"Pod","metadata":{"name":"`+long+`","namespace":"x"},"spec":{"hostNetwork":true},
		 "status":{"phase":"Running","containerStatuses":[{"imageID":"x@`+web+`","state":{"running":{}}}]}},
		{"kind":"Pod","metadata":{"name":"p","namespace":"x"},
		 "status":{"phase":"Running","containerStatuses":[{"imageID":"x@sha256:abc","state":{"running":{}}},{"imageID":"`+web+`x","state":{"running":{}}}]}}]}`), "c", taken)
	if err != nil {
		t.Fatal(err)
	}
	if c := (Set{inv}).Lookup(web); c.Pods != 1 || len(c.Exposure[0]) > 200 {
		t.Errorf("malformed digests are ignored and reasons bounded: %+v", c)
	}
}

func TestParseBoundsAndAttribution(t *testing.T) {
	// The object limit holds while decoding: a small file of empty items fails early.
	many := `{"items":[` + strings.Repeat(`{},`, MaxItems) + `{}],"kind":"List"}`
	if _, err := Parse([]byte(many), "c", taken); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("object limit: %v", err)
	}
	// kubectl prints kind after items; a native sidecar (running init container) counts, with
	// its host port; a route to another namespace's Service needs a ReferenceGrant, not seen.
	in := `{"apiVersion":"v1","items":[
	 {"kind":"Pod","metadata":{"name":"p","namespace":"pay","labels":{"app":"pay"}},
	  "spec":{"initContainers":[{"name":"mesh","ports":[{"hostPort":15000}]}],"containers":[{"name":"app"}]},
	  "status":{"phase":"Running","initContainerStatuses":[{"imageID":"x@` + agent + `","state":{"running":{}}}],
	   "containerStatuses":[{"imageID":"x@` + web + `","state":{"running":{}}}]}},
	 {"kind":"Pod","metadata":{"name":"q","namespace":"pay","labels":{"app":"api"}},
	  "status":{"phase":"Running","containerStatuses":[{"imageID":"x@` + api + `","state":{"running":{}}}]}},
	 {"kind":"Service","metadata":{"name":"api","namespace":"pay"},"spec":{"type":"ClusterIP","selector":{"app":"api"}}},
	 {"kind":"HTTPRoute","metadata":{"name":"steal","namespace":"tenant"},"spec":{"rules":[{"backendRefs":[{"name":"api","namespace":"pay"}]}]}}
	],"kind":"List","metadata":{}}`
	inv, err := Parse([]byte(in), "prod", taken)
	if err != nil {
		t.Fatal(err)
	}
	set := Set{inv}
	if c := set.Lookup(agent); !c.Running || !c.Exposed || !strings.Contains(c.Exposure[0], "hostPort") {
		t.Errorf("native sidecar: %+v", c)
	}
	if c := set.Lookup(api); !c.Running || c.Exposed {
		t.Errorf("a route from another namespace does not expose: %+v", c)
	}
	if c := set.Lookup(web, web); c.Pods != 1 {
		t.Errorf("one digest given twice counts once: %+v", c)
	}
}

func TestLoadRefusesStaleExports(t *testing.T) {
	p := filepath.Join(t.TempDir(), "prod.json")
	if err := os.WriteFile(p, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, taken, taken); err != nil {
		t.Fatal(err)
	}
	inv, err := Load(p, "prod", 24*time.Hour, taken.Add(time.Hour))
	if err != nil || !inv.Taken.Equal(taken) || inv.Cluster != "prod" {
		t.Fatalf("fresh export: %+v, %v", inv, err)
	}
	if _, err := Load(p, "prod", 24*time.Hour, taken.Add(25*time.Hour)); !errors.Is(err, ErrStale) {
		t.Errorf("stale export: %v", err)
	}
	if _, err := Load(p, "prod", 0, taken.AddDate(1, 0, 0)); err != nil {
		t.Errorf("no age limit: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json"), "prod", 0, taken); err == nil {
		t.Error("missing export accepted")
	}
	if _, err := Load(p, "prod", 24*time.Hour, taken.Add(-time.Hour)); !errors.Is(err, ErrStale) {
		t.Errorf("an export from the future cannot be judged fresh: %v", err)
	}
	if _, err := Load(t.TempDir(), "prod", 0, taken); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Errorf("a directory is no export: %v", err)
	}
}
