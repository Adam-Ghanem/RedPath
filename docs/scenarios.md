# Scenario library and assessment history

RedPath now includes a curated scenario layer that turns individual analyzers into repeatable purple-team playbooks. Every scenario is observation-driven and defaults to dry-run mode. A playbook can analyze synthetic AD observations, compare imported Wazuh alerts, calculate a prioritized risk score, and persist a concise assessment history record in SQLite.

## Included playbooks

| Scenario | Purpose | Techniques | Safety boundary |
| --- | --- | --- | --- |
| `ad.identity-exposure-baseline` | Review service-account SPNs and Kerberos pre-authentication state | `T1558.003`, `T1558.004` | Observation-only; no ticket requests or password attacks |
| `ad.adcs-template-review` | Review authentication certificate-template metadata | `T1649` | Metadata-only; no certificate enrollment |
| `purple.kerberos-detection-battle` | Compare expected Kerberos signals with Wazuh evidence | `T1558.003`, `T1558.004` | Synthetic events and read-only alert imports |
| `purple.path-to-domain-admin` | Prioritize modeled paths using risk and chokepoint context | `T1558.003`, `T1649` | In-memory graph exercise; no privilege escalation |

## API workflow

Use `GET /api/v1/scenarios` to retrieve the catalog. Submit observation and alert evidence to `POST /api/v1/scenarios/{scenario_id}/run`. The request body contains `scenario_id`, `observations`, `alerts`, and an explicit `dry_run` flag. The response contains finding count, risk score, detection coverage, gaps, recommendations, and a generated run identifier.

Use `GET /api/v1/runs` to retrieve the most recent persisted summaries. The default SQLite file is `data/redpath.db`, which is ignored by Git and mounted through the Docker Compose data volume. Audit entries continue to be written to `data/audit.jsonl`.

```bash
curl http://127.0.0.1:8000/api/v1/scenarios

curl -X POST http://127.0.0.1:8000/api/v1/scenarios/ad.identity-exposure-baseline/run \
  -H 'Content-Type: application/json' \
  -d @lab/fixtures/scenario_run.json

curl http://127.0.0.1:8000/api/v1/runs
```

The React console exposes the same workflow through the **Scenario library** panel. It uses seeded playbooks when the API is offline and switches to the live scenario catalog and persisted run history when the API is online.
