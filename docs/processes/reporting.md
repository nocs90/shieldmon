# Monthly reporting

```sh
shieldmon report monthly --month 2026-10 -o html --out reports/2026-10.html  # self-contained summary for stakeholders
shieldmon report monthly --month 2026-10 -o md  --out reports/2026-10.md
shieldmon report monthly --month 2026-10 -o csv --out reports/2026-10.csv   # remediation-plan worksheet
shieldmon report monthly --month 2026-10 -o json --out reports/2026-10.json
```

The report is computed from the append-only audit trail, so it can be regenerated for any
past month with identical results. Files are written 0600 (they are an inventory of
weaknesses).

| Metric | Definition |
|---|---|
| Open at start/end | findings whose state at that instant is open, reopened, triaged or in_remediation |
| Newly opened | new lineages first detected in the period (carry-overs to new digests are not new) |
| Fixed | transitions to `fixed` in the period (scan evidence) |
| MTTR | fixed time − inherited first detection, mean and median, for fixes in the period |
| Open past SLA | open findings older than the SLA for their severity (`sla.profile`) |
| Burndown | open count at end of each day |
| Monitoring health | open health findings: gaps in the evidence itself |

The current month is reported "as of now". Deadlines come from `sla.profile` and
`sla.days` in the configuration.
