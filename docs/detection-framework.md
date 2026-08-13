# Detection Rule, Correlation, and Regression Framework

## Purpose

RedPath now includes a process-scoped detection engineering slice for evaluating read-only Wazuh-style events against safe, declarative rules. The framework keeps detection logic data-driven: rules contain bounded field paths, explicit comparison operators, ATT&CK technique mappings, event-source allow-lists, grouping keys, and correlation windows. It does not execute rule text, shell commands, network actions, or user-provided code.

The evaluator is intentionally suitable for synthetic lab replay and offline telemetry analysis. A rule can correlate multiple conditions across events from the same group within a bounded time window. Events without parseable timestamps remain evaluable, but they do not receive a time-window guarantee; production ingestion should provide normalized timestamps.

## Rule contract

A rule is represented by `DetectionRule` in `backend/app/schemas/contracts.py` and contains the following controls.

| Field | Meaning |
| --- | --- |
| `rule_id` | Stable lower-case identifier used by evaluations and regression fixtures. |
| `version` | Positive rule revision number included in evaluation provenance and reports. |
| `technique_ids` | One or more ATT&CK technique identifiers covered by the rule. |
| `event_sources` | Case-insensitive source allow-list; the current built-ins use `wazuh`. |
| `conditions` | One to ten bounded field comparisons using `equals`, `contains`, `starts_with`, or `in`. |
| `match_mode` | `all` requires every condition; `any` requires at least one. |
| `window_seconds` | Correlation window from one second through 24 hours. |
| `group_by` | Optional event fields that prevent unrelated principals or hosts from being correlated. |
| `deployment_status` | `draft`, `testing`, or `production`. Production rules must retain `requires_approval=true`. |
| `false_positive_sla_percent` | The quality threshold to review during rule tuning. |

Field paths are limited to alphanumeric characters, dots, hyphens, and underscores. Evaluation reads only the validated `WazuhAlert` model representation. The `in` operator accepts only a list, and boolean equality uses strict boolean identity rather than string coercion.

## Correlation semantics

For each enabled rule, events are first filtered by the rule’s event-source allow-list and then partitioned by `group_by`. The evaluator checks each condition within each group, combines evidence from the condition-matching events, and accepts a match only when the rule’s match mode is satisfied and the evidence is within `window_seconds`. A match returns the rule, techniques, deterministic sorted alert IDs, matched condition count, group key, parsed first/last timestamps, and a human-readable rationale.

An event with no ID may contribute to condition satisfaction, but it cannot appear in the alert evidence list. A rule with no `group_by` uses the single `all-events` group. Unknown rule IDs return a not-found API response rather than being silently ignored.

## Regression semantics

Regression fixtures are positive or negative expectations over a rule and a bounded list of synthetic events. The runner reports each case’s expected and actual outcomes, evidence IDs, pass/fail state, total cases, and quality metrics. True-positive rate is the percentage of positive fixtures that matched. False-positive rate is the percentage of negative fixtures that matched. The overall run is `passed` only when every fixture passes.

The built-in suite covers a positive and negative Kerberoasting case, a positive AS-REP case, and a positive AD CS template-risk case. The built-in fixtures are synthetic and are intended to verify rule behavior, not to represent live attack traffic.

## Normalized telemetry and evidence

Read-only Wazuh ingestion projects source documents into `TelemetryEvent`, a bounded analyst record containing tenant ID, event ID, timestamp, severity, rule metadata, asset ID, ATT&CK technique IDs, summary, an allow-listed scalar `safe_fields` map, and a SHA-256 digest of the source document. The detection adapter consumes only this redacted projection. It does not pass raw Wazuh documents, commands, credentials, packet contents, or arbitrary nested fields to the evaluator or response.

The normalized evaluator returns the server-selected tenant and actor context, rule version, deterministic rule-content SHA-256 provenance, matched telemetry event IDs, and optional attack-path evidence IDs. Attack-path evidence is accepted only as a bounded projection containing a stable `path-<12 hex>` identifier, tenant, risk level/score, technique IDs, asset IDs, summary, and timezone-aware capture time. Raw graph payloads are not accepted by the coverage or regression contracts. A path is linked to a rule only when its technique set intersects the rule’s technique set.

## Deterministic coverage and regression reporting

`POST /detections/coverage` calculates rule coverage as detected selected rules divided by selected rules, rounded to two decimal places. Path coverage is the number of linked path evidence IDs divided by supplied path evidence IDs. Rule ordering, event IDs, path IDs, provenance entries, and observation contents are sorted or derived deterministically; the run identifier and timestamps are execution metadata only.

`POST /detections/regressions/normalized` accepts bounded normalized telemetry fixtures and optional bounded path evidence. Each case reports only expected/actual outcome, pass/fail state, telemetry event IDs, path evidence IDs, and a short note. It returns true-positive and false-positive rates, rule provenance, server-derived tenant and actor, dry-run status, and warnings. It never returns `safe_fields` or raw source payloads.

## API endpoints

All endpoints are under `/api/v1` and record an audit event. Rule registration remains process-scoped; it does not deploy rules to Wazuh or persist them to a SIEM. Deployment approval and durable rule storage are integration points for platform orchestration and governance.

| Method and path | Contract | Behavior |
| --- | --- | --- |
| `GET /detections/rules` | `list[DetectionRule]` | Lists built-in and process-registered enabled/disabled rules. |
| `POST /detections/rules` | `DetectionRuleCreate` → `DetectionRule` | Registers a new rule in the current process. Duplicate IDs and unapproved production rules are rejected. |
| `POST /detections/evaluate` | `DetectionEvaluationRequest` → `DetectionEvaluationResponse` | Evaluates events against all selected rules or all catalog rules when `rule_ids` is empty. |
| `POST /detections/regressions/run` | `RegressionRunRequest` → `RegressionReport` | Runs supplied fixtures, or the built-in synthetic suite when `fixtures` is omitted. |
| `POST /detections/coverage` | `DetectionCoverageRequest` → `DetectionCoverageReport` | Scores selected rules against normalized telemetry and bounded attack-path evidence. |
| `POST /detections/regressions/normalized` | `NormalizedRegressionRequest` → `NormalizedRegressionReport` | Runs tenant-safe regression fixtures over normalized telemetry without returning raw payloads. |

Detection, telemetry, coverage, regression, evidence, and attack-path routes are placed behind the project’s server-side bearer authentication, `analyze` permission, rate limiting, tenant checks, and audit policy. The authenticated principal’s tenant and username are used for report context and audit actor values; request payloads cannot override either. The feature remains read-only with respect to external systems and honors the application’s dry-run default.

## Focused validation

The focused suite is `backend/tests/test_detection_framework.py`. It verifies built-in rule matching, same-group and time-window correlation, regression quality metrics, endpoint wiring, approval enforcement, and unknown-rule handling. The repository-wide commands are:

```bash
pytest -q
ruff check backend
bandit -r backend/app -c pyproject.toml
```
