# Governance-grade control model

RedPath v3 adds decision governance without turning the platform into an autonomous enforcement system. A reviewer can accept a documented risk for a bounded period, move evidence through a review state, update remediation lifecycle state, and inspect control-coverage KPIs derived from stored assessment evidence.

| Domain | Policy | Audit expectation |
| --- | --- | --- |
| Risk acceptance | Requires approver, rationale, expiry date, linked technique or finding, and explicit status | Acceptance and expiry are audit events; expired acceptance never hides the finding |
| Evidence review | `unreviewed`, `in_review`, `accepted`, `rejected` | Review transitions preserve source, digest, reviewer, and timestamp |
| Remediation lifecycle | `open`, `in_progress`, `blocked`, `resolved`, `closed` | Updates preserve owner, priority, SLA state, and transition actor |
| Control coverage | Scorecards compare expected techniques, detected techniques, open gaps, and accepted risks | Accepted risk is visible as a separate state rather than counted as detected |
| Executive KPI | Aggregates risk, coverage, overdue actions, open critical items, and expiring acceptances | Every value points back to local persisted records |

The v3 API is still lab-safe. It does not close findings automatically, modify Wazuh rules, change Active Directory, or treat an accepted risk as a security control. Risk acceptance is a time-bounded governance decision that remains visible in exports and executive KPIs.
