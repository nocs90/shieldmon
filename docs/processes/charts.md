# Following Helm charts

Normative rules: [ADR 0032](../adr/0032-chart-sources.md) (sources) and
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

Until ShieldMon renders charts itself, render where you deploy and add the images with
`targets add --manifests` (docs/processes/manifest-images.md).
