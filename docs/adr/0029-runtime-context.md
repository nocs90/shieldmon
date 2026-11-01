# 0029 — Runtime context from read-only cluster exports, as priority only

- Status: accepted
- Date: 2026-11-01

## Context

- A finding in an image that runs, and is reachable from outside the cluster, matters more
  than the same finding in an image nobody runs (#38, as in Wiz and Prisma Cloud). ADR 0020's
  score knows severity, exploitation, fix and SLA clock, not where an image runs.
- #38 asks for no agent. An in-cluster agent, or a kubeconfig in ShieldMon, would give the
  monitoring host credentials to every cluster it reports on; THREAT_MODEL keeps ShieldMon's
  credentials to registries only.
- `kubectl get pods,services,ingresses,httproutes -A -o json` prints a `List` that already
  holds what is needed: running pods, the image digest each container's kubelet pulled
  (`status.containerStatuses[].imageID`: `repo@sha256:…`, `docker-pullable://repo@sha256:…`
  or `sha256:…`), pod labels, `hostNetwork` and `hostPort`, Services with their type and
  selector, Ingress and Gateway API route backends. A `view` ClusterRole can produce it.
- The kubelet reports the digest it pulled by, the index digest for a multi-platform tag;
  ShieldMon scans the platform manifest and records the index it came from (`artifacts`).
- Object names and labels in the export come from every tenant of the cluster: hostile input.
- Reports are evidence of a period (ADR 0018): where images run today says nothing about a
  past month.

## Decision

- `runtime.inventories` lists one export file per cluster; `internal/runtimectx` reads them
  (at most 256 MiB and 500,000 objects; names truncated; any malformed object refuses the
  export) and answers, per image digest, how many running pods use it and, at most three
  examples of, how one is exposed:
  - a Service of type LoadBalancer or NodePort, or with `externalIPs`, selecting the pod (same
    namespace, non-empty selector);
  - an Ingress, or an HTTPRoute, GRPCRoute, TLSRoute, TCPRoute or UDPRoute, whose backend is a
    Service selecting the pod, in the route's own namespace (another namespace needs a
    ReferenceGrant the export does not hold: a route the Gateway rejects must not make another
    tenant's image look exposed);
  - `hostNetwork` or a `hostPort`.
  A pod counts when its phase is Running, an image when its container, ephemeral container or
  still-running init container (a native sidecar) is running. A pod's exposure covers all its
  containers. Items are decoded one at a time, so the object limit holds before allocation.
- An export that is not a regular file, is older than `runtime.max_age` (default 48h, by file
  time), dated more than 5 minutes in the future, or malformed is left out with a warning;
  runtime context never fails a command.
- The index digest matches every platform of the index: pods on amd64 nodes mark the findings
  of the arm64 manifest too. Monitored platforms are usually those the clusters run; when not,
  the boost is a reason to look, not a claim.
- Priority (ADR 0020) gains two parts, the total still capped at 100:

  | Part | Points |
  |---|---|
  | Running in a monitored cluster | 5 |
  | … and reachable from outside the cluster | 10 more |

  An image is matched by its platform manifest digest or its index digest. Absence never
  lowers a score: an image no export shows keeps ADR 0020's score.
- Runtime context only orders: it changes no state, SLA clock, gate decision (a CI gate
  judges an image before it runs) or export.
- `findings list` shows it (`runtime` in JSON) and ranks with it. The monthly report applies
  only exports taken within the (half-open) period up to its generation; it lists every
  configured export, with whether it applied and why not (taken outside the period, stale,
  unreadable), counts open findings in running and exposed images, and adds a `runtime`
  column to the remediation plan: `running (N pods)…`, or `not seen in the applied exports`,
  never "not running", since a cluster without a usable export may run the image.

## Consequences

- No agent and no cluster credential in ShieldMon: a scheduled job in each cluster, with view
  rights, writes the export where ShieldMon reads it (docs/processes/runtime-context.md).
- Exposure through what the export does not show (a cloud load balancer to a ClusterIP, a
  service mesh gateway, NetworkPolicies that close a NodePort) is not seen; exposure is a
  lower bound, and a reason to look, not proof.
- Reports of past months are not reranked with today's exports; a report generated late in
  its month uses the latest export.
- Exports change no table: nothing about where an image ran is kept beyond the files
  themselves. Historical runtime evidence, if needed, is a later design.
