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
