# VEX statements about ShieldMon's own image

`shieldmon-image.openvex.json` holds the reviewed `not_affected` statements the dogfooding
gate (ci/image) imports before judging the image it just built
(docs/processes/quality-gates.md). The image bundles syft, grype and trivy release binaries,
so their dependencies are judged like ShieldMon's own.

Rules for adding a statement:

- One vulnerability, scoped to the image repositories and to the **exact** package version,
  in every form the scanners write it (`pkg:golang/stdlib@1.26.8` from syft,
  `pkg:golang/stdlib@v1.26.8` from trivy), so that a new scanner release is judged again.
  Copy the PURLs from the gate's SARIF (`dogfood-report` artifact), not from its table.
- An OpenVEX justification and an impact statement that a reviewer can check against the
  advisory: why the vulnerable code is absent or unreachable in this image.
- An expiry (`expires:` in `status_notes`), at most three months out.
- Reviewed in a pull request like code. Bumping a scanner (scripts/install-scanners.sh) is the
  fix; a statement is for what does not apply until then.
