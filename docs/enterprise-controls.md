# Enterprise control model

The enterprise upgrade treats every assessment as a reviewable chain of custody rather than a collection of UI actions. RedPath remains a local lab platform, but each control is explicit and testable.

| Control | Invariant | Exposed outcome |
| --- | --- | --- |
| Audit integrity | Every audit entry references the previous digest and the verifier reports the first broken link | `GET /api/v1/integrity/audit` |
| Evidence provenance | Imported evidence has a canonical metadata manifest and a SHA-256 digest format check | `POST /api/v1/evidence/manifest` |
| Remediation SLA | Priority maps to an expected response window and open items are classified as on-track, due-soon, or overdue | `GET /api/v1/remediations/sla` |
| Campaign export | Export contains campaign metadata, timeline, evidence metadata, remediation state, trend points, and a manifest digest | `GET /api/v1/campaigns/{campaign_id}/export` |
| Safety boundary | Export and verification are read-only; no operation can mutate AD, Wazuh, or external lab systems | Audit record plus dry-run defaults |

The export is deliberately a JSON package, not a claim of cryptographic signing. It includes a canonical SHA-256 manifest digest so a future signing adapter can wrap the package with an organization-controlled key without changing the domain model. The current implementation does not invent or persist private keys.

Remediation SLA windows are deterministic product policy: critical items target 7 days, high 14 days, medium 30 days, and low 60 days. The API reports the policy classification and does not silently change due dates or close items.
