# 0030 — Targets from rendered manifests; rendering stays outside ShieldMon

- Status: accepted
- Date: 2026-11-01

## Context

- F11 (#6) wants every image a Helm chart runs monitored: containers, init containers,
  ephemeral containers and hook Jobs, with the chart version, and the images rendering cannot
  reveal (operator-managed) flagged.
- Rendering a chart (`helm template`) executes the chart's templates with its values: a
  third-party chart is code. Embedding the Helm SDK adds a large dependency tree; running the
  `helm` binary adds a scanner-like tool to pin, sign-check and sandbox (ADR 0006, 0011). The
  chart sources (HTTP repositories, OCI, Artifact Hub) and per-version tracking are their own
  design (`ChartSource`, still planned in the epic).
- Teams already render: Argo CD, Flux and CI pipelines run `helm template` or `kustomize build`,
  and `kubectl get -o yaml` shows what is deployed. The rendered YAML holds the images and the
  `helm.sh/chart` label (name-version) and `helm.sh/hook` annotation Helm adds.
- Operators create pods from custom resources (a CloudNativePG `Cluster`, a Prometheus
  operator `Prometheus`): their images appear in no manifest.

## Decision

- `shieldmon targets add --manifests FILE` ("-": stdin) reads rendered manifests (multi-document
  YAML, or a JSON object or List) with `internal/manifests` and adds the image of every
  container, init container and ephemeral container of Pods, Deployments, StatefulSets,
  DaemonSets, ReplicaSets, ReplicationControllers, Jobs, CronJobs and PodTemplates; hooks
  included, and noted when only hooks use an image.
- Objects of API groups that are not Kubernetes' own are custom resources: each is listed as
  a warning ("images its operator runs are not in the manifests"), so that someone adds them.
- Lists are read in both forms: a YAML `kind: List` (`kubectl get -o yaml`) and JSON Lists,
  typed lists included (`DeploymentList` from the raw API, whose items carry no kind). A
  custom resource whose kind ends in "List" is not a List.
- Nothing must pass for "no images": input without any Kubernetes object (a render that failed
  and printed nothing), or a document without `kind` (a values file), fails the command. Every
  image must be a valid reference: one that is not (an empty image, a value the chart left
  unrendered) fails the command and adds nothing, rather than leaving a workload unmonitored
  silently. A container without an image fails the read.
- Everything is decoded with yaml.v3, JSON too: field names match case-sensitively, as the API
  server reads them, and duplicate keys are refused, so a crafted `"Containers"` cannot hide
  the containers that run.
- Inputs are bounded before decoding: 64 MiB in all, 2 MiB per YAML document or JSON List item
  (the API server stores about 1.5 MiB per object; a decoded tree costs many times its text),
  100,000 objects, 10,000 distinct images; YAML aliasing and nesting are limited by the parser.
  Names are truncated and printed escaped, in errors too; nothing in the manifests is executed
  or fetched.
- Rendering, chart sources and chart-version tracking stay out of this decision.

## Consequences

- A chart is monitored by piping its rendering: `helm template … | shieldmon targets add
  --manifests -`, in the same pipeline that deploys it, with the values it deploys with.
- Images an operator creates, or that a chart computes at runtime, still need `targets add` by
  hand; the warning says where.
- Neglected-chart detection (a fix available upstream that a chart has not adopted) needs the
  chart sources and versions over time: the next step of #6, building on the `helm.sh/chart`
  label read here.
