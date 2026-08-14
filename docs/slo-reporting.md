# SLO and error-budget reporting

RedPath release reporting uses aggregate counters only. The report contains no request bodies, query values, packet bytes, raw SIEM records, customer data, credentials, or tenant identifiers. The local verifier consumes a synthetic fixture; production operators may supply an approved aggregate export through a protected, read-only process.

## Input contract

`ci/report_slo.py` accepts JSON with `window_minutes`, `requests_total`, `server_errors`, `ready_checks_total`, `ready_failures`, `latency_ms`, `audit_failures`, and `tenant_boundary_failures`. The window is bounded to 1–43,200 minutes, latency samples are bounded to 10,000 values from 0–300,000 ms, and counters must be non-negative and internally consistent.

## Targets and error budget

| SLO | Target | Budget behavior |
| --- | --- | --- |
| Readiness availability | At least 99.5% | Remaining availability budget is calculated from readiness checks |
| Server error rate | At most 1% | Remaining error budget is calculated from request count and 5xx count |
| Read-only API p95 latency | At most 1,000 ms | A latency breach pauses promotion; it does not trigger unbounded retries |
| Audit integrity | Zero failures | Any failure pauses promotion and preserves diagnostics read-only |
| Tenant boundary checks | Zero failures | Any failure fails closed and pauses promotion |

The report returns `status=pass` only when every target and integrity control passes. Otherwise it returns `status=pause_promotion` and the safe response `pause promotion and preserve aggregate diagnostics`. An exhausted error budget is a release decision, not an instruction to disable controls or mutate production state.

## Commands

Run the deterministic report with the synthetic fixture:

```bash
PYTHONPATH=backend python ci/report_slo.py --input ci/fixtures/slo-sample.json --json
```

The release evidence manifest records this command. Production use requires an approved aggregate input, a protected read-only access path, an operator, a reviewer, and an incident record when the report pauses promotion.
