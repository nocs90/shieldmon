# Report test data

| File | Source |
|---|---|
| `remediation-plan.golden.csv` | output of `TestRemediationPlanGolden`; regenerate with `go test ./internal/report -update` and review the diff |
| `sarif-schema-2.1.0.json` | OASIS SARIF 2.1.0 (errata 01) schema, from [oasis-tcs/sarif-spec](https://github.com/oasis-tcs/sarif-spec) at commit `1742a253eb654bf8a4ed7c60eaef7412b2c23553`, `sarif-2.1/schema/sarif-schema-2.1.0.json` (sha256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`) |
