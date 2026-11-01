# Runtime context: which images run, and which are exposed

Normative rules: [ADR 0029](../adr/0029-runtime-context.md). This page is the runbook.

ShieldMon runs no agent and holds no cluster credential. Each cluster exports, on a schedule,
what runs in it; ShieldMon reads the files and ranks findings of running images higher, of
exposed ones higher still. Nothing else changes: states, SLA clocks, the CI gate and exports
are the same with or without runtime context.

## 1. Export from each cluster

A CronJob (or any scheduler) in the cluster, with a ServiceAccount allowed to list pods,
services, ingresses and Gateway API routes, writes one file:

```sh
kubectl get pods,services,ingresses,httproutes -A -o json > prod.json
```

- Leave out kinds the cluster does not have (`httproutes` needs the Gateway API CRDs); add
  `grpcroutes`, `tlsroutes`, `tcproutes`, `udproutes` if used.
- The built-in `view` ClusterRole covers pods, services and ingresses; routes need a rule for
  `gateway.networking.k8s.io` (`get`, `list`). Nothing needs secrets or write rights.
- Deliver the file to the ShieldMon host (a shared volume, an object store sync): ShieldMon
  only reads it. Its modification time is when it was taken: keep the sync from preserving a
  remote timestamp in the future.
- An export is refused above 256 MiB or 500,000 objects. Large clusters (or a tenant with
  huge annotations) stay under it by dropping what ShieldMon does not read:

  ```sh
  kubectl get pods,services,ingresses,httproutes -A -o json \
    | jq -c '.items[] |= del(.metadata.annotations, .metadata.managedFields)' > prod.json
  ```

## 2. Configure

```yaml
runtime:
  max_age: 48h          # older exports are left out, with a warning
  inventories:
    - { cluster: prod, path: /var/lib/shieldmon/runtime/prod.json }
    - { cluster: stage, path: /var/lib/shieldmon/runtime/stage.json }
```

Export more often than `max_age` (daily for a daily monitoring cycle). A missing, malformed or
stale export prints `warning: runtime context of cluster prod left out: …` and the command goes
on without it.

## 3. Where it shows

| Where | What |
|---|---|
| `findings list --sort priority` | running and exposed images first; `-o json` adds `runtime` (`pods`, `exposed`, `exposure`) and the reasons in `priority.reasons` |
| `report monthly` (md, html, json) | a "Runtime context" section: exports considered, whether each applied, open findings in running and exposed images; per row `runtime` and the reranked `priority` in JSON |
| remediation plan (`-o remediation-plan`, `remediation-plan-excel`) | a `runtime` column: `running (N pods); exposed: …`, `not seen in the applied exports`, or empty when no export applied |

A monthly report applies only exports taken within its month, up to when it is generated:
the report of a past month is not reranked with today's exports, and says so.

## What counts

- **Running**: a pod in phase Running whose container, ephemeral container or native sidecar
  (an init container still running) is running the image, matched by the digest the kubelet
  pulled: ShieldMon matches it to the platform manifest it scanned or to the index digest it
  resolved from (an index digest matches all its platforms).
- **Exposed**: the pod is selected by a Service of type LoadBalancer or NodePort, or with
  external IPs; or by a Service an Ingress or a Gateway API route in the same namespace sends
  traffic to; or it uses the host network or a host port.
- Not seen: exposure the export does not show (cloud load balancers to a ClusterIP Service,
  mesh gateways, routes to another namespace through a ReferenceGrant), and NetworkPolicies
  that close a port. Treat "exposed" as a reason to look first, and "not exposed" or "not
  seen" as unknown, not as safe.
- A report lists every configured export and why one did not apply; a warning on stderr is
  not enough for a scheduled job, so read that section when an export goes missing.
