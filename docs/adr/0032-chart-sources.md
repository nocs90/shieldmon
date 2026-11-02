# 0032 — Chart sources: versions and archives of Helm charts, checked before rendering

- Status: accepted
- Date: 2026-11-01

## Context

- F11 (#6) follows Helm charts: which versions exist, what each one runs, and whether a chart
  keeps shipping images with fixable vulnerabilities. ADR 0030 covers manifests a team
  renders itself; following a chart over its versions needs its archives.
- Charts are published three ways: HTTP chart repositories (`index.yaml` with each version's
  archive URL and SHA-256), OCI registries (`helm push`: an OCI manifest whose config is
  `application/vnd.cncf.helm.config.v1+json` and whose single layer is the archive,
  `application/vnd.cncf.helm.chart.content.v1.tar+gzip`; tags are versions with `+` written
  `_`), and Artifact Hub, an index of both (`/api/v1/packages/helm/<repo>/<chart>` names the
  repository URL). Checked live on 2026-11-01: ingress-nginx (HTTP), Bitnami's nginx (OCI on
  Docker Hub; Bitnami's HTTP index now points to `oci://` archives), podinfo (Artifact Hub).
- A chart archive is third-party content that a renderer will read: a tarball can hold links,
  absolute or `..` paths, a second archive appended after the first, or expand to gigabytes.
- Registry credentials stay in `internal/oci` (rules).

## Decision

- **Extension point** `internal/charts`: `Source` (`Versions`, newest first by SemVer, at most
  1,000; `Fetch`, at most 16 MiB, returning the archive's digest; `Location`), a registry
  (`charts.Register`) and a conformance kit (`chartstest.CheckPlugin`, `CheckSource`), like
  scanners and registry providers (ADR 0008). Built in:
  - `http`: `index.yaml` (at most 32 MiB) of an HTTPS repository (HTTP to localhost only, no
    credentials in URLs); archive URLs resolve against the repository as a directory; the
    archive's SHA-256 must match the index's when the index has one; `oci://` archive URLs are
    fetched through the registry access.
  - `oci`: tags of `<repository>/<chart>` through the configured registry providers, archives
    through `oci.FetchChart`, which requires Helm's config media type and exactly one chart
    layer, checks its declared size before downloading, and verifies it against its digest.
  - `artifacthub`: asks Artifact Hub once where the chart lives and reads it from there, with
    the `http` or `oci` source: Artifact Hub is never trusted for content.
- **Remote content reaches public addresses only.** URLs the configuration names (a
  repository, Artifact Hub's API) are fetched as configured, HTTPS (HTTP to localhost for a
  mirror), following at most 5 HTTPS redirects (object storage). URLs that remote content names
  — an index's archive URL on another host, the repository Artifact Hub answers with — must be
  HTTPS and are fetched with a client that connects only to public addresses, checked on the
  address actually dialled (no loopback, private, link-local, carrier-grade NAT, multicast or
  unspecified address, whatever the name resolves to; through an environment proxy, the proxy
  decides). Registry references from remote content may not name a loopback, private or
  link-local address or localhost; registries are dialled by go-containerregistry, so a public
  name resolving to an internal address is a residual risk. An index digest that is present
  but not a SHA-256 fails the fetch rather than skip verification.
- **Archive check** before anything renders an archive (`charts.CheckArchive`), in the archive
  and in every bundled subchart (`charts/*.tgz`, which Helm loads), on one budget: regular
  files and directories only, no absolute or escaping path, no duplicate entry, one top-level
  directory named after the chart, at most 10,000 entries and 64 MiB unpacked (headers
  counted), subcharts nested at most 3 deep, nothing but padding after the end of an archive,
  and a `Chart.yaml` naming the chart and version asked for, with no key that Helm's
  case-insensitive reader would read otherwise (`Name:` next to `name:`).
- Configuration `charts:` lists the charts followed (`chart`, `source`, `options`, an optional
  `name`); `shieldmon charts list | versions | fetch` uses them. The newest version is the
  newest SemVer that is neither a pre-release nor deprecated.

## Consequences

- Rendering (with a pinned, sandboxed `helm`) and tracking per chart version build on these
  sources and on ADR 0030's manifest parser; they are their own decisions.
- Private HTTP chart repositories (basic auth) are not supported yet; private OCI charts use the
  registries' credentials.
- OCI tags that are not chart versions (signatures, `latest`) are skipped; a pre-release tag
  that is not a chart (Bitnami's `-metadata`) is listed but never chosen as newest.
