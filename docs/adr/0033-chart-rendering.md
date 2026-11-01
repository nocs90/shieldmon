# 0033 — Chart rendering: a pinned helm in the scanners' sandbox, per profile

- Status: accepted
- Date: 2026-11-01

## Context

- F11 (#6) needs the images a chart runs. They are known only once the chart is rendered:
  templates choose images from values (a registry mirror, an optional sidecar, a tag built
  from `.Chart.AppVersion`), so the same version runs different images in different
  installations. ADR 0030 parses rendered manifests; ADR 0032 fetches and checks archives.
- Templates of a third-party chart are code. Helm's template language has no file or process
  access outside the chart, but it has functions that reach the network (`getHostByName`),
  values schemas may refer to remote schemas, and the template engine can be made to spend
  CPU and memory. Reimplementing Helm's rendering (Sprig, subcharts, `tpl`, library charts,
  hooks) is not credible: the renderer must be Helm.
- Helm signs each release archive with OpenPGP (a `.asc` per archive, keys in the `KEYS` file
  of its repository); it does not publish Sigstore signatures.

## Decision

- **helm is pinned and verified like the scanners** (ADR 0006): `scripts/install-scanners.sh`
  installs helm 4.3.1 (released 2026-10-15) with its SHA-256 recorded in the script, and
  requires a valid OpenPGP signature of the archive made by a key whose primary fingerprint
  is pinned (`208DD36ED5BB3745A16743A4C7C6FBB5B91C1155`, the maintainer who signed the
  release), taken from Helm's `KEYS` at a pinned commit, itself pinned by SHA-256, imported
  into a keyring of its own. A good signature by another key in `KEYS` is refused. `HELM=0`
  skips helm (verification needs `gpg`). The container image carries it. `helm.path` and
  `helm.sha256` configure and pin it; `doctor` reports it when charts are configured.
- **Rendering runs through `scanner.Runner`, in the scanners' sandbox** (ADR 0011), with a
  policy of its own (`charts.Renderer`): no network; read access to one private staging
  directory holding the archive and the profile's values, and nothing else of the host; the
  scanners' DB cache not visible; a private scratch directory as `HOME`, where helm keeps its
  configuration, cache and plugins (none: `XDG_*` emptied, `HELM_*`, `KUBECONFIG` and
  credentials never passed, the environment allowlist unchanged); time bounded by
  `helm.timeout` (2 minutes by default), output by the manifest parser's 64 MiB, scratch by
  the scanners' quota. The archive is checked again (`charts.CheckArchive`) right before it
  is staged.
- **Only `helm template`**, never against a cluster: no `--validate`, so `lookup` finds
  nothing; `--namespace` always given, so no kubeconfig is read; `.Capabilities` come from the
  profile (`kube_version`, `api_versions`); no `--dependency-update`, so dependencies not
  bundled in `charts/` fail the render instead of being downloaded; no post-renderer.
  Every value reaches helm as one `--flag=value` argument, and the release name and archive
  path follow `--`; release names follow Helm's rule, namespaces DNS labels.
- **Profiles**: a chart is rendered once per configured profile (`charts[].profiles`: name,
  release, namespace, `values_files` then inline `values`, later ones winning as with `-f`);
  none means one `default` profile with the chart's own values. Values come from the
  configuration (at most 32 documents, 4 MiB in all). A schema that needs remote schemas
  cannot load offline: `skip_schema_validation` skips the chart's schema for that profile.
- The rendered manifests go through the manifest parser (ADR 0030): bounds, workloads,
  hooks, custom resources. `shieldmon charts images NAME` lists them per profile;
  `shieldmon targets add --chart NAME` adds them as targets.

## Consequences

- Under `scanners.sandbox.backend: none`, helm runs unconfined as the scanners do (a
  `scanner_unsandboxed` health finding stays open): templates can then resolve names
  (`getHostByName`) and read the environment helm itself reads.
- Memory is not bounded by the sandbox; a chart that makes the template engine allocate
  without limit is stopped by the timeout or by the memory limits of the deployment.
- OpenPGP verification trusts one maintainer key: a release signed by another maintainer
  fails until the pin is reviewed and updated, which bumping helm checks anyway.
- Tracking charts per version (which images each version runs, neglected charts) builds on
  `Renderer` and is its own decision.
