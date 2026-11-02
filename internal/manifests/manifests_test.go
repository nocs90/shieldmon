package manifests

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// rendered is shaped like `helm template shop ./shop` output.
const rendered = `---
# Source: shop/templates/serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: shop
  labels:
    helm.sh/chart: shop-1.4.2
---
# Source: shop/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: shop-web
  namespace: shop
  labels:
    helm.sh/chart: shop-1.4.2
    app.kubernetes.io/managed-by: Helm
spec:
  replicas: 2
  template:
    metadata:
      labels: {app: web}
    spec:
      initContainers:
        - name: migrate
          image: "ghcr.io/acme/shop-migrate:1.4.2"
      containers:
        - name: web
          image: "ghcr.io/acme/shop:1.4.2"
          ports: [{containerPort: 8080}]
        - name: proxy
          image: docker.io/envoyproxy/envoy@sha256:1111111111111111111111111111111111111111111111111111111111111111
---
# Source: shop/templates/cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: shop-report
  labels:
    helm.sh/chart: shop-1.4.2
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: report
              image: ghcr.io/acme/shop:1.4.2
          restartPolicy: OnFailure
---
# Source: shop/templates/tests/test-connection.yaml
apiVersion: v1
kind: Pod
metadata:
  name: "shop-test-connection"
  annotations:
    "helm.sh/hook": test
spec:
  containers:
    - name: wget
      image: busybox:1.36
---
# Source: shop/templates/postgres.yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: shop-db
  namespace: shop
spec:
  instances: 3
  imageName: ghcr.io/cloudnative-pg/postgresql:16.2
---
`

func TestParseRenderedChart(t *testing.T) {
	r, err := Parse(strings.NewReader(rendered))
	if err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, img := range r.Images {
		refs = append(refs, img.Ref)
	}
	want := []string{
		"busybox:1.36",
		"docker.io/envoyproxy/envoy@sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"ghcr.io/acme/shop-migrate:1.4.2",
		"ghcr.io/acme/shop:1.4.2",
	}
	if !slices.Equal(refs, want) || r.Workloads != 3 {
		t.Fatalf("images %q, workloads %d", refs, r.Workloads)
	}
	shop := r.Images[3]
	if !slices.Equal(shop.Where, []string{"Deployment shop/shop-web (container web)", "CronJob default/shop-report (container report)"}) ||
		!slices.Equal(shop.Charts, []string{"shop-1.4.2"}) || shop.Hook {
		t.Errorf("shop: %+v", shop)
	}
	if mig := r.Images[2]; !strings.Contains(mig.Where[0], "init container migrate") {
		t.Errorf("init containers count: %+v", mig)
	}
	if bb := r.Images[0]; !bb.Hook || len(bb.Charts) != 0 {
		t.Errorf("an image used only by a Helm test hook is marked: %+v", bb)
	}
	if len(r.Opaque) != 1 || r.Opaque[0].Kind != "Cluster" || r.Opaque[0].APIVersion != "postgresql.cnpg.io/v1" {
		t.Errorf("custom resources are flagged, their images unknown: %+v", r.Opaque)
	}
}

func TestParseKubectlJSON(t *testing.T) {
	list := `{"apiVersion":"v1","kind":"List","items":[
	 {"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"db","namespace":"data"},
	  "spec":{"template":{"spec":{"containers":[{"name":"pg","image":"postgres:16"}]}}}},
	 {"apiVersion":"v1","kind":"Pod","metadata":{"name":"dbg","namespace":"data"},
	  "spec":{"containers":[{"name":"app","image":"postgres:16"}],"ephemeralContainers":[{"name":"debugger","image":"busybox:1.36"}]}}]}`
	r, err := Parse(strings.NewReader(list))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Images) != 2 || r.Workloads != 2 || len(r.Images[1].Where) != 2 || !strings.Contains(r.Images[0].Where[0], "ephemeral container debugger") {
		t.Errorf("%+v", r)
	}
}

func TestParseLists(t *testing.T) {
	// kubectl get -o yaml prints one List document.
	yamlList := `apiVersion: v1
kind: List
items:
- apiVersion: extensions/v1beta1
  kind: DaemonSet
  metadata: {name: legacy, namespace: kube-system}
  spec:
    template:
      spec:
        containers: [{name: agent, image: "quay.io/acme/agent:1"}]
- apiVersion: acme.io/v1
  kind: AllowList
  metadata: {name: ips}
metadata:
  resourceVersion: ""
`
	r, err := Parse(strings.NewReader(yamlList))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Images) != 1 || r.Images[0].Ref != "quay.io/acme/agent:1" || r.Objects != 2 {
		t.Errorf("YAML List, legacy extensions group: %+v", r)
	}
	if len(r.Opaque) != 1 || r.Opaque[0].Kind != "AllowList" {
		t.Errorf("a custom resource whose kind ends in List is a custom resource: %+v", r.Opaque)
	}

	// The raw API returns typed lists whose items carry no kind; JSON keys match exactly.
	typed := `{"kind":"DeploymentList","apiVersion":"apps/v1","metadata":{},"items":[
	 {"metadata":{"name":"web","namespace":"shop"},"spec":{"template":{"spec":{
	   "containers":[{"name":"web","image":"ghcr.io/acme/web:2"}],
	   "Containers":[{"name":"decoy","image":"alpine:3"}]}}}}]}`
	r, err = Parse(strings.NewReader(typed))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Images) != 1 || r.Images[0].Ref != "ghcr.io/acme/web:2" || !strings.HasPrefix(r.Images[0].Where[0], "Deployment shop/web") {
		t.Errorf("typed list items get the list's kind; field names are case-sensitive: %+v", r)
	}
}

func TestParseRefusesWhatIsNoManifest(t *testing.T) {
	for what, in := range map[string]string{
		"empty (a render that failed)": "",
		"only separators and comments": "---\n# nothing\n---\n",
		"a values file":                "replicaCount: 2\nimage: {repository: x}\n",
		"an empty JSON List":           `{"kind":"List","apiVersion":"v1","items":[]}`,
	} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
	if _, err := Parse(strings.NewReader("")); !errors.Is(err, ErrNoObjects) {
		t.Errorf("empty input: %v", err)
	}
	if r, err := Parse(strings.NewReader("apiVersion: v1\nkind: Service\nmetadata: {name: s}\n")); err != nil || r.Workloads != 0 || r.Objects != 1 {
		t.Errorf("manifests without workloads are fine: %+v, %v", r, err)
	}
}

func TestParseRefusesHostileInput(t *testing.T) {
	for what, in := range map[string]string{
		"missing image":  "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers: [{name: a}]\n",
		"broken yaml":    "apiVersion: v1\nkind: Pod\nspec: [\n",
		"wrong types":    "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template: 3\n",
		"nested lists":   `{"kind":"List","items":[{"kind":"List","items":[]}]}`,
		"billion laughs": "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\nd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\ne: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\nf: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\ng: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]\nh: [*g,*g,*g,*g,*g,*g,*g,*g,*g]\nkind: Pod\nspec: {containers: *g}\n",
	} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
	if _, err := Parse(strings.NewReader(strings.Repeat("#", MaxBytes+1))); err == nil {
		t.Error("oversized input accepted")
	}
	big := "apiVersion: v1\nkind: ConfigMap\ndata:\n" + strings.Repeat("  k: [a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a,a]\n", MaxObjectBytes/90+1)
	if _, err := Parse(strings.NewReader(big)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("a document is bounded before it is decoded: %v", err)
	}
	var many strings.Builder
	for i := range MaxImages + 1 {
		fmt.Fprintf(&many, "---\napiVersion: v1\nkind: Pod\nmetadata: {name: p%d}\nspec: {containers: [{name: c, image: \"x:%d\"}]}\n", i, i)
	}
	if _, err := Parse(strings.NewReader(many.String())); err == nil || !strings.Contains(err.Error(), "distinct images") {
		t.Errorf("the images one input adds are bounded: %v", err)
	}
	long := strings.Repeat("é", 200)
	r, err := Parse(strings.NewReader("apiVersion: v1\nkind: Pod\nmetadata: {name: " + long + "}\nspec:\n  containers: [{name: " + long + ", image: x:1}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if w := r.Images[0].Where[0]; len(w) > 400 || !strings.Contains(w, "…") {
		t.Errorf("names are bounded: %d bytes", len(w))
	}
}
