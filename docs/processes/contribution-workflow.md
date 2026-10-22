# From issue to merged PR

```
issue (template) → triage (labels, milestone, Project) → branch → commits (-s) → PR (template)
   → quality gates → review (CODEOWNERS, + security review if sensitive) → squash merge
   → issue closed by "Closes #N" → Project card to Done → release notes
```

1. **Pick or open an issue.** Use the forms (bug / feature / adapter). Unlabelled issues
   carry `needs-triage`; a maintainer adds `kind/*`, `area/*`, `priority/*` and a milestone
   ([issue-management.md](issue-management.md)). Comment to claim it.
2. **Design first when needed.** Data model, lifecycle, extension interfaces or security
   posture changes start with an ADR in `docs/adr/` (copy `0000-template.md`).
3. **Branch** from `main`: `feat/<area>-<short>`, `fix/<area>-<short>`.
4. **Commit** with sign-off (`git commit -s`) and Conventional Commit messages.
5. **Verify locally**: `make lint test-unit`; `make test-integration` when touching
   scanner/oci/engine; `make fuzz` when touching a parser.
6. **Open the PR** with the template; title in Conventional Commits form (checked by CI);
   link `Closes #N`. Add `run/integration` to run the integration job on the PR.
7. **Review**: CODEOWNERS approval required. Security-sensitive paths (oci, scanner,
   redact, lifecycle, migrations, install script, workflows) need a maintainer.
8. **Merge**: squash, PR title becomes the commit message.
