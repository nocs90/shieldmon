# Monitoring the images of Helm charts and Kubernetes manifests

Normative rules: [ADR 0030](../adr/0030-manifest-images.md). This page is the runbook.

ShieldMon does not render charts: render where you deploy, with the values you deploy with,
and hand the result to ShieldMon.

```sh
set -o pipefail   # a failed render must fail the job, not reach ShieldMon as a short input

# A Helm chart, as deployed
helm template shop oci://registry.example.com/charts/shop --version 1.4.2 -f values-prod.yaml \
  | shieldmon targets add --manifests - --dry-run

# A kustomize overlay
kustomize build overlays/prod | shieldmon targets add --manifests -

# What runs in a namespace now
kubectl get deploy,sts,ds,cronjob,job -n shop -o yaml > shop.yaml
shieldmon targets add --manifests shop.yaml
```

`--dry-run` shows the references that would be added. Then:

- The image of every container, init container and ephemeral container of Pods, Deployments,
  StatefulSets, DaemonSets, ReplicaSets, Jobs, CronJobs and PodTemplates is added; already
  monitored references are skipped as with any `targets add`.
- `note: … is used by Helm hooks only` marks images of install/upgrade Jobs and tests: they run
  briefly, but they run.
- `warning: Cluster shop/shop-db (postgresql.cnpg.io/v1) is a custom resource` means an
  operator creates pods for it whose images the manifests do not show: look them up in the
  operator's documentation or in the cluster (`kubectl get pods -n shop -o yaml`) and add them.
- An image that is not a valid reference (an empty `image:`, a value the chart did not render)
  fails the command and adds nothing: fix the values, or the chart. So does input without any
  Kubernetes object (an empty pipe) or with a document that has no `kind` (a values file).
- A YAML document or a JSON List item above 2 MiB is refused (no real object is that large);
  a very large `kubectl get -o yaml` List is better given as `-o json`, whose items are read
  one at a time. One input adds at most 10,000 distinct images.
- An image that matches a retired target is not added again: the output names the target and
  the `targets restore` command that brings it back, a decision with its own record, when the
  chart still runs it.

Run it in the deployment pipeline so that a chart upgrade adds its new images in the same
change; retire the images it no longer uses with `targets retire` (ADR 0017).
