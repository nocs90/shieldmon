# Releases

> Status: manual until the release pipeline issue (M2) lands. This page describes the
> target process; steps marked ⬜ are not automated yet.

1. Milestone's definition of done passes in CI; open issues moved or closed.
2. Update SPEC status column, ROADMAP, and write release notes from merged PR titles
   (Conventional Commits → changelog).
3. Tag `vX.Y.Z` on `main` (signed tag).
4. ⬜ goreleaser builds reproducible binaries (linux/darwin, amd64/arm64), checksums and
   an SBOM of ShieldMon itself.
5. ⬜ cosign keyless signatures + SLSA provenance attached to the release.
6. ⬜ Container image built, signed, and scanned by ShieldMon (dogfooding).
7. Announce in Discussions; breaking changes called out explicitly.

Versioning: SemVer; pre-1.0 minors may break configuration.
