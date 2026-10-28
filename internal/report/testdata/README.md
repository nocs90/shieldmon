# Report test data

| File | Source |
|---|---|
| `remediation-plan.golden.csv` | output of `TestRemediationPlanGolden`; regenerate with `go test ./internal/report -update` and review the diff |
| `cyclonedx/*.schema.json` | CycloneDX 1.6 JSON schema with the SPDX and JSF schemas it references, from [CycloneDX/specification](https://github.com/CycloneDX/specification) at commit `ad83dae28b236b8760286399da4daba77592de86`, `schema/` (sha256: bom-1.6 `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d`, spdx `4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359`, jsf-0.82 `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae`) |
| `inventory.golden.*` | output of `TestInventory` and `TestInventoryCycloneDX`; regenerate with `-update` and review the diff |
| `sarif-schema-2.1.0.json` | OASIS SARIF 2.1.0 (errata 01) schema, from [oasis-tcs/sarif-spec](https://github.com/oasis-tcs/sarif-spec) at commit `1742a253eb654bf8a4ed7c60eaef7412b2c23553`, `sarif-2.1/schema/sarif-schema-2.1.0.json` (sha256 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`) |
