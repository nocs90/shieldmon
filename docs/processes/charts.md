# Following Helm charts

Normative rules: [ADR 0032](../adr/0032-chart-sources.md) (sources),
[ADR 0033](../adr/0033-chart-rendering.md) (rendering) and
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

- `release` defaults to the chart's name in ShieldMon, `namespace` to `default`.
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
