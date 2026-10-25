# Conformance kit

`internal/scanner/scannertest` is the contract an adapter must satisfy. It is what makes
external contributions safe to merge: reviewers check the kit passes instead of
re-deriving every edge case.

| Helper | Checks |
|---|---|
| `CheckPlugin(t, name)` | registered; has a description; constructs with defaults; implements Generator and/or Matcher; names match; a matcher's generator is registered and is a Generator |
| `CheckParser(t, scanner, parse, fixtures...)` | real fixtures parse with Scanner set, non-empty IDs, PURL or name+version, valid severity; output survives normalization; hostile inputs (empty, HTML error page, truncated JSON, wrong types, 10k-deep nesting, control bytes) never panic and never yield matches |
| `CheckMatcher(t, m, sbom)` (integration) | real run reports tool name, version and DB build time; honours context cancellation |
| `CheckSandbox(t, backend)` | runs through a Runner with a scratch quota, as in production. Registered with a description; confines (is not the `none` opt-out); a probe process inside it can read its inputs, write its output and scratch directories, and write the DB cache and connect only when the policy grants network; it cannot read or list anything else (home directory included), write its inputs, write outside its policy, write the DB cache or connect while offline, start a child in a new user namespace or turn off ASLR with `personality` (the seccomp filter), execute a script it wrote in its scratch or output directory (W^X; skipped, with a log line, where the backend reports itself degraded through `scanner.Degrader`), fill its scratch space past the quota (`ErrScratchQuota`), write a file larger than the quota (a DB update may), or leave a child running after a timeout. Skipped where the backend cannot run, unless `SHIELDMON_TEST_SANDBOX` (comma-separated) names it |

Built-in adapters and sandbox backends run the kit in `internal/scanner/conformance_test.go`.
The sandbox probe is the test binary re-running itself (`scannertest` hooks `init`), so a
backend needs no shell or network tools inside the sandbox to be tested. Reads are judged by
the content returned and writes by what reaches the host, not by whether the call
succeeded: a backend may show the process stand-in paths (bwrap creates the parents of its
mounts inside the scratch directory, so a write there succeeds and is discarded). When a new
extension point is added, it ships with its own kit in the same style.
