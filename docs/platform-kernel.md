# Platform Contracts and Integration Kernel

The platform kernel provides the control-plane boundary that connects RedPath modules without allowing domain integrations to bypass shared safety controls. The implementation lives in `backend/app/kernel/`, while plugin metadata and adapters remain under `backend/app/plugins/`. The kernel is deliberately narrow: it validates typed context, resolves a registered read-only plugin, invokes declarative planning or observation analysis, and records metadata-only audit events.

> The kernel plans and analyzes; it does not execute shell commands, perform uncontrolled discovery, persist raw payloads, or grant permissions.

## Contract versioning

All new kernel payloads carry `schema_version: "1.0"`. Unknown fields are rejected on the kernel-owned Pydantic models. `IntegrationContext` is frozen after validation so an integration cannot mutate tenant, actor, request, target, or dry-run attributes during a call.

| Contract | Purpose | Important invariants |
| --- | --- | --- |
| `IntegrationContextRequest` | API input for planning | Strict fields; bounded tenant, actor, request ID, and target counts |
| `IntegrationAnalysisRequest` | API input for analysis | Adds at most 256 observation dictionaries |
| `IntegrationContext` | Internal call context | Versioned, strict, frozen, control-character-free targets |
| `PlannedAction` | Declarative plan item | Read-only, bounded operation enum, no command or shell field |
| `IntegrationPlan` | Plan response | Versioned, plugin identity, request identity, actions, warnings |
| `NormalizedObservation` | Analyzer input | Versioned, tenant-tagged, bounded metadata envelope |
| `IntegrationAnalysis` | Analyzer response | Versioned, plugin identity, observation count, typed findings, warnings |

The shared `Asset` contract remains under `backend/app/models/domain.py`. It is intentionally independent from the kernel envelope so asset inventory, PCAP, SIEM, and detection modules can use the same domain object without coupling their transport concerns.

## Plugin registry

A plugin exposes a `PluginManifest`, `plan(context)`, and `analyze(context, observations)`. Manifests declare a stable lower-case identifier, version, capabilities, ATT&CK technique IDs, required permission scopes, dry-run support, and read-only status. `PluginRegistry` validates identifiers, rejects duplicate registrations, rejects empty capabilities, and rejects any manifest that is not read-only.

The default registry currently exposes the following adapters.

| Plugin ID | Capability boundary | Required scope | Execution posture |
| --- | --- | --- | --- |
| `recon.safe_inventory` | Safe asset/service inventory planning | `asset.read` | Read-only; dry-run supported |
| `ad.observation_analyzer` | AD observation analysis | `evidence.read` | Read-only; dry-run supported |
| `purple.wazuh_gap_report` | Wazuh detection-gap analysis | `telemetry.read` | Read-only; dry-run supported |

The default adapters are deliberately conservative placeholders. They produce a typed plan or bounded analysis result and emit a warning when a domain-specific executor or analyzer has not yet been registered. Future modules should register an implementation rather than adding domain logic to the kernel.

## Kernel lifecycle

The `IntegrationKernel` accepts an injectable registry, scope validator, and audit recorder. For each request, it resolves the plugin, verifies that the requested mode is supported, invokes the configured scope validator for target-bearing operations, and then delegates to the plugin. For analysis, every observation is normalized and its `tenant_id` must match the context tenant before plugin code receives it.

```text
API request
   -> strict request model
   -> IntegrationContext construction
   -> plugin lookup and manifest checks
   -> allow-list scope hook for targets
   -> declarative plan OR normalized observation analysis
   -> metadata-only audit event
   -> typed response
```

The API applies the environment dry-run setting as the safer value: `effective_dry_run = settings.dry_run or request.dry_run`. The route never accepts an executable command, arbitrary shell text, or a plugin implementation from the request body. An unknown plugin returns `404`; an out-of-scope target returns `403`; malformed or cross-tenant observations return `422`.

## API examples

Create a dry-run plan for an allow-listed lab target:

```http
POST /api/v1/integrations/recon.safe_inventory/plan
Content-Type: application/json

{
  "tenant_id": "tenant-a",
  "actor": "analyst-1",
  "request_id": "plan-1",
  "targets": ["192.168.56.10"],
  "dry_run": true
}
```

The response contains only declarative actions:

```json
{
  "schema_version": "1.0",
  "plugin_id": "recon.safe_inventory",
  "plugin_version": "0.1.0",
  "request_id": "plan-1",
  "dry_run": true,
  "actions": [
    {
      "action_id": "recon.safe_inventory:plan",
      "operation": "collect",
      "description": "Prepare Safe service inventory within the authorized integration boundary.",
      "targets": ["192.168.56.10"],
      "required_permissions": ["asset.read"],
      "read_only": true,
      "dry_run": true
    }
  ],
  "warnings": ["This registry adapter only plans work; domain execution remains outside the kernel."]
}
```

Analyze a normalized, tenant-tagged observation set:

```http
POST /api/v1/integrations/ad.observation_analyzer/analyze
Content-Type: application/json

{
  "tenant_id": "tenant-a",
  "actor": "analyst-1",
  "request_id": "analysis-1",
  "dry_run": true,
  "observations": [
    {
      "observation_id": "obs-1",
      "tenant_id": "tenant-a",
      "source": "fixture",
      "attributes": {"technique_id": "T1558.003"}
    }
  ]
}
```

The kernel does not log observation attributes. Audit entries contain only plugin, request, tenant, actor, mode, and count metadata so raw evidence remains in the evidence-plane workflows owned by later milestones.

## Integration responsibilities

The kernel owns orchestration invariants, but each domain module retains responsibility for its own typed semantics. A network-discovery module must continue to use the existing CIDR allow-list and safe command runner. A PCAP module must parse offline evidence without live capture side effects. A Wazuh adapter must remain read-only. Detection, graph, case, remediation, and reporting modules should return the shared contracts and avoid embedding transport or authorization logic in analyzers.

Every future plugin should provide focused contract tests for manifest validation, dry-run behavior, tenant isolation, scope failures, and typed result construction. Long-running work belongs in a worker boundary introduced by a later orchestration milestone; this synchronous kernel does not create background jobs or execute external actions.

## Verification

The platform kernel is covered by `backend/tests/test_kernel.py`. The complete backend suite and lint command used for delivery are:

```bash
pytest -q backend/tests
ruff check backend/app backend/tests
```

See the repository’s [architecture guide](architecture.md) for the broader control-plane/evidence-plane model and [contribution guide](../CONTRIBUTING.md) for branch and review conventions.


## Stable extension API

The kernel extension API provides an additive negotiation step before planning or analysis. `CapabilityNegotiationRequest` contains only a requested contract version, optional capability IDs, request ID, and dry-run preference. Tenant and actor identity are not accepted in this negotiation body; the API derives them from the authenticated principal. The response reports the plugin version, selected contract version, capability descriptors, compatibility decision, unsupported capabilities, and a structured error when selection is not possible.

A plugin manifest declares its module kind, capabilities, supported contract versions, required permission labels, read-only status, and dry-run support. The registry rejects mutating or non-dry-run plugins at registration. The kernel rejects incompatible contract versions and unsupported capability requests before a plugin plan or analyzer is invoked. Existing plan and analyze routes remain available, while `POST /api/v1/integrations/{plugin_id}/negotiate` exposes the explicit compatibility check.

| Module kind | Safe contract fixture | Boundary |
| --- | --- | --- |
| `pcap` | `pcap.offline_analysis` | Analyze registered offline evidence; no live capture, packet injection, or packet mutation |
| `telemetry` | `telemetry.read_only` | Read bounded, redacted telemetry; no rule writes, alert acknowledgement, or remote SIEM mutation |
| `discovery` | `discovery.safe_inventory` | Use approved scope and rate limits; no uncontrolled scanning |
| `detection` | `detection.observation_rules` | Analyze normalized observations and regression fixtures; no automatic rule deployment |
| `graph` | `graph.exposure_risk` | Evaluate explicit relationships and evidence; no exploit execution |
| `case` | `case.evidence_linking` | Link evidence-backed findings; no destructive remediation or external ticket mutation |

## Structured errors and pagination

`IntegrationError` is the stable error envelope for kernel consumers. It contains an allow-listed code, safe message, request ID, optional plugin ID, bounded string details, and a retryable flag. The API maps it to an HTTP status while preserving structured fields. Error messages do not include stack traces, raw payloads, credentials, command text, or sensitive target values. Existing status behavior remains compatible for unknown plugins (`404`), scope rejection (`403`), and malformed or cross-tenant observations (`422`).

`PaginationRequest`, `PaginationMetadata`, `Page[T]`, and `PluginCatalogPage` provide a bounded cursor contract for catalog consumers. Page size is limited to 100, cursors are restricted to non-negative offsets at the transport boundary, and the catalog is sorted by stable plugin ID. The legacy `/api/v1/plugins` list remains available for compatibility; `/api/v1/plugins/catalog` exposes the versioned page envelope.

## Security invariants

All sensitive integration routes remain behind authentication and the existing `read` or `analyze` RBAC dependencies. The API derives tenant and actor from the authenticated principal and ignores client-supplied tenant and actor fields retained only for backward-compatible request parsing. The kernel validates target scope through the existing allow-list hook, preserves the environment-level dry-run override, enforces tenant equality on normalized observations, and records only metadata counts and server-derived identity through the existing audit chain.

The contract fixtures in `backend/tests/fixtures/kernel_modules.py` use synthetic observations containing only evidence references and scalar metadata. They do not connect to live hosts, capture traffic, send packets, query remote SIEM services, modify detection rules, mutate cases, or execute commands. The contract tests cover all six module kinds, exact version negotiation, unsupported capabilities, structured unknown-plugin errors, pagination, tenant isolation, protected catalog access, and server-derived actor behavior.

## Extension API verification

Focused extension and kernel regression coverage is run with:

```bash
pytest -q backend/tests/test_kernel_extension.py backend/tests/test_kernel.py
```

The full backend suite and frontend quality gates remain required before merge. Downstream module contributors should implement against the negotiation and page envelopes, keep adapter-specific schemas behind their module boundary, and add fixture tests before registering a new capability.


## Version and event compatibility

The public integration contract is versioned independently from implementation versions. The current accepted contract version is `1.0`; unknown versions are rejected for execution contexts and event envelopes. Capability negotiation may receive a future version so it can return a structured incompatibility decision without invoking a plugin. A plugin may advertise only versions accepted by the platform policy, and a plan or analysis request is dispatched only after both platform and plugin compatibility checks pass.

`EventEnvelope` is the stable event boundary. It carries a schema marker, contract version, event identity, event type, occurrence time, tenant ID, server-derived actor, request ID, and a bounded scalar metadata payload. Raw packet data, raw telemetry, credentials, tokens, commands, stack traces, and arbitrary nested payloads do not cross this envelope. Consumers must treat unknown event versions as non-processable and retain the original event for review rather than guessing its meaning.

`Page[T]` and `PaginationMetadata` provide bounded list responses with a maximum page size of 100 and a bounded forward cursor. Producers must keep ordering stable within a query and must not use client-provided cursors to bypass tenant or resource authorization. Consumers must handle `has_more` and `next_cursor` explicitly rather than assuming a complete result set.

Contract-only changes do not require a database migration. When persistence is changed, follow the additive workflow in [migrations.md](migrations.md), run the migration checker twice against a temporary database, and provide an application-revert, snapshot-restore, or forward-compensating rollback decision. No destructive rollback SQL is part of the automated path.
