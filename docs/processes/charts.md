# Following Helm charts

Normative rules: [ADR 0032](../adr/0032-chart-sources.md) (sources),
[ADR 0033](../adr/0033-chart-rendering.md) (rendering),
[ADR 0034](../adr/0034-chart-tracking.md) (tracking, neglected charts) and
[ADR 0030](../adr/0030-manifest-images.md) (images of rendered manifests). This page is the
runbook.

## 1. Declare the charts

```yaml
charts:
  - { chart: ingress-nginx, source: http, options: { url: https://kubernetes.github.io/ingress-nginx } }
  - { chart: nginx, source: oci, options: { repository: registry-1.docker.io/bitnamicharts } }
  - { name: podinfo, chart: podinfo, source: artifacthub, options: { repository: podinfo } }
```

- `http`: the chart repository's URL (where `index.yaml` is); HTTPS only.
- `oci`: the registry path above the chart (`helm pull oci://<repository>/<chart>`); private
  registries use the credentials of `registries:` (docs/processes/registries.md).
- `artifacthub`: the Artifact Hub repository name; ShieldMon asks Artifact Hub where the chart
  lives and reads versions and archives from there.
- `name` is how ShieldMon calls the chart (default: the chart's name); give one when two
  sources hold charts of the same name.

## 2. Look

```sh
shieldmon charts list                        # configured charts and where they come from
shieldmon charts versions ingress-nginx      # newest first
shieldmon charts fetch ingress-nginx --out ingress-nginx.tgz            # newest release
shieldmon charts fetch nginx --version 25.2.12 --out nginx-25.2.12.tgz
```

`fetch` checks the archive as ShieldMon does before rendering one: regular files only, no path
leaving the chart, at most 10,000 entries and 64 MiB unpacked, nothing appended after the
archive, a `Chart.yaml` naming the chart and version asked for, and the digest the index
publishes. A failure names what is wrong; nothing in the archive is run.

## 3. Describe how each chart is installed

The images a chart runs depend on its values. Give a chart one profile per installation;
without profiles it is rendered once, as `default`, with the chart's own values.

```yaml
charts:
  - chart: ingress-nginx
    source: http
    options: { url: https://kubernetes.github.io/ingress-nginx }
    profiles:
      - { name: prod, namespace: ingress, values_files: [/etc/shieldmon/values/ingress-prod.yaml] }
      - name: mirror
        values: { global: { image: { registry: mirror.example.com } } }
        kube_version: "1.33"
        api_versions: [monitoring.coreos.com/v1]
```

- `release` defaults to the chart's name in ShieldMon (`.` and `_` as `-`, at most 53
  characters), `namespace` to `default`. Templates set namespaces themselves, usually from the
  release's: objects of a chart that does not are listed in `default`.
- `values_files` apply in order, then `values`; later ones win, as with `helm -f`. Keep the
  files where you keep the deployment's values (the same review), readable by ShieldMon.
- `kube_version` and `api_versions` are what templates see as `.Capabilities`: nothing talks
  to a cluster. Set them like the cluster the profile describes when a chart renders
  differently on it (CRD-dependent objects, API versions).
- `skip_schema_validation: true` for a chart whose `values.schema.json` refers to remote
  schemas: rendering has no network.

## 4. Render and add the images

helm comes from `scripts/install-scanners.sh` (pinned, signature-verified; in the container
image already). Pin it in the configuration and check it:

```sh
shieldmon doctor                                 # helm path, sha256 and pin
shieldmon charts images ingress-nginx            # newest release, every profile
shieldmon charts images ingress-nginx --version 4.12.0 --profile prod -o json
shieldmon targets add --chart ingress-nginx --dry-run
shieldmon targets add --chart ingress-nginx --profile prod
```

Rendering is `helm template` in the scanners' sandbox: no network, nothing of the host but the
checked archive and the profile's values, bounded time (`helm.timeout`) and output. A render
fails, naming the profile, when the chart needs a dependency that is not bundled, a remote
schema, or values it rejects; fix the profile, not the sandbox.

What the listing means is the same as for `targets add --manifests`
(docs/processes/manifest-images.md): hook-only images are marked, and custom resources are
listed because the operator they configure may run images the manifests do not show; add those
by hand.

## 5. Follow releases

`shieldmon monitor` follows every configured chart at the start of each cycle: the newest
release (not a pre-release, not deprecated) is rendered with each profile the first time, and
again only when its archive or a profile changes; every render is recorded (append-only,
audited). With `add_targets: true` the release's images become targets and are scanned in the
same cycle; without it, add them with `targets add --chart`. The chart's publisher chooses those
images, so `add_targets` adds only images on public registries or on registries you configured
in `registries:` (an internal mirror: configure it there), and at most `max_new_targets` (50)
new ones per release; anything else opens `chart_failed` with the images named, for you to
review with `targets add --chart NAME --dry-run`.

```sh
shieldmon charts track                 # the same, now, without scanning
shieldmon charts history ingress-nginx # every release recorded, images added (+) and dropped (-)
```

A chart that cannot be followed opens `chart_failed` (docs/processes/health-findings.md) and
the cycle is `degraded`; its targets are still scanned. Images a new release no longer runs
stay targets: retire them when nothing runs them any more (`targets retire`, with a reason).

## 6. Neglected charts

```sh
shieldmon charts status                # every chart: release, images, monitored, with a fix, neglected
shieldmon charts status ingress-nginx -o md > charts.md
```

A chart is **neglected** when its newest release ships an image with an active finding that
has a fix, of at least `chart_policy.min_severity` (`high`), detected more than
`chart_policy.fixable_after` ago (`720h`), or when it has not released for
`chart_policy.stale_after` (`4320h`) and its source dates releases. A chart with images that
are not scanned targets is `unknown`, not clean: add them, or wait for the next cycle.

What to do with a neglected chart, in order:

1. Check the chart's newer pre-releases and its issue tracker: a fix may be on its way.
2. Override the image in the profile's values (`image.tag`, a registry mirror) to a release
   with the fix, if the chart allows it, and keep the profile in review with the deployment.
3. Tell the maintainers. `shieldmon charts draft-issue NAME` prints a Markdown draft with the
   overdue findings: review it, follow the project's CONTRIBUTING (templates, sign-off),
   search its issues for an existing report, and submit it yourself. ShieldMon never submits
   anything upstream.
4. If the chart is abandoned, plan a replacement and record the risk decision on the findings
   meanwhile (docs/processes/triage-and-decisions.md).
