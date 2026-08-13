# Governed Detection Lifecycle

RedPath’s detection lifecycle is a defensive, read-only workflow for reviewing declarative rules and synthetic normalized telemetry before a rule is considered ready for broader deployment. It does not execute rule text, mutate Wazuh, connect to external networks, access credentials, or perform attack simulation.

## Detection-as-code package convention

A detection package is represented by a versioned manifest under `detections/pack.json`. The manifest identifies the pack, owner, pack version, rule IDs and rule revisions, fixture assignments, and measurable baselines. Synthetic normalized fixtures live under `detections/fixtures/` and are metadata-only. A fixture names the rule under test, states the expected outcome, includes bounded `TelemetryEvent` projections, and may include bounded attack-path evidence projections. Raw Wazuh documents, commands, credentials, packet contents, and arbitrary nested data are not valid fixture content.

| Package element | Required governance |
| --- | --- |
| `pack_id` and `pack_version` | Stable lower-case identity and positive revision number. |
| `owner` | Named accountable owner for the package. |
| `rules` | Stable rule ID, exact rule version, and one or more fixture IDs. |
| `baseline` | Minimum true-positive rate, maximum false-positive rate, minimum rule coverage, and optional path-coverage threshold. |
| Fixture | Stable ID, rule assignment, expected outcome, bounded normalized telemetry, and optional bounded path evidence. |

Rules remain declarative. Conditions are limited to the existing safe operators (`equals`, `contains`, `starts_with`, and `in`) over validated field paths. The lifecycle validator rejects unsupported MITRE technique IDs, unsafe condition paths or values containing credential, secret, exploit, persistence, evasion, injection, malware, or destructive terms, and production rules without explicit approval evidence.

## Rule metadata and approval states

Each `DetectionRule` includes a schema version, revision number, owner, tags, telemetry requirements, coverage type, mean-time-to-detect target, false-positive SLA, deployment status, approval state, reviewer, and review timestamp. A production rule must retain `requires_approval=true`, use `approval_state=approved`, and include both `reviewed_by` and `reviewed_at`. A rejected rule is not silently promoted; a new revision should be reviewed instead.

The current built-in rules are intentionally in `testing` status. They map to the local MITRE registry and identify the normalized Wazuh source required for evaluation. The package validator treats a valid MITRE mapping and safe logic as hard gates, while missing owner or telemetry metadata is a warning for non-production rules.

## Regression and coverage baselines

The lifecycle gate runs the selected pack fixtures through the normalized regression evaluator, then calculates deterministic rule coverage from the deduplicated normalized telemetry set. It reports true-positive rate, false-positive rate, rule coverage, path coverage, rule-content provenance hashes, fixture outcomes, telemetry IDs, and rationale. The gate passes only when every fixture is structurally valid, all selected rule mappings are safe, and the observed metrics meet the pack baseline.

A structural or tenant-validation error produces `blocked`, while a validly evaluated pack that misses a configured baseline produces `failed`. This distinction makes CI failures actionable without treating malformed or cross-tenant input as a detection-quality result. The gate always runs in dry-run mode in the repository script.

## API and CI entry points

The protected API endpoint `POST /api/v1/detections/lifecycle/gate` accepts a pack manifest and fixture list. It requires the existing `analyze` permission, derives tenant and actor identity from the authenticated session, records a chained audit event with counts and identifiers, and returns no raw telemetry values. The application-level dry-run setting takes precedence over a request that asks for execution.

The CI-ready command is:

```bash
python3 scripts/validate_detection_pack.py
```

It loads `detections/pack.json` and `detections/fixtures/core.json`, evaluates them against the process-scoped defensive catalog, prints a deterministic JSON report, and exits with status `0` only for a passing gate. The command has no network, subprocess, or external-state behavior.

## Integration and security notes

The identity layer remains the source of truth for tenant and actor context. Detection reports must be linked to cases, evidence, and attack-path analysis by stable IDs and provenance hashes rather than by copying raw telemetry. The analyst console can display rule status, revision, approval state, rationale, baseline metrics, fixture outcomes, and coverage gaps. The risk engine should treat detection output as evidence with a known provenance, not as proof of compromise.

The lifecycle stores no new database records, so no migration or rollback is required. Existing audit logging is used for the protected gate endpoint. Privacy controls are preserved by using only normalized redacted telemetry, excluding arbitrary payload fields from responses, and rejecting unknown fields in the new lifecycle models. Safe failure is explicit: unauthenticated callers receive HTTP 401, callers without `analyze` permission receive HTTP 403, malformed packs receive HTTP 422 or a `blocked` report, and no failed validation triggers remote mutation.
