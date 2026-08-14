# Detection Plugin Development

RedPath plugins are **read-only, dry-run control-plane adapters**. A plugin may plan analysis or transform normalized observations into typed findings, but it must not execute shell commands, scan arbitrary targets, alter tenant data, or perform remediation.

## DetectionPlugin contract

Detection integrations should extend `DetectionPluginBase` from `backend/app/plugins/base.py` and provide a `PluginManifest` whose `module_kind` is `detection`. The base class supplies the safe `plan()` and `analyze()` lifecycle. Implement `detect(context, observations)` with normalized `NormalizedObservation` objects and return `FindingInput` models.

```python
from app.kernel.contracts import IntegrationContext, ModuleKind, NormalizedObservation
from app.plugins.base import DetectionPluginBase, PluginManifest
from app.schemas.contracts import FindingInput


class ExampleDetectionPlugin(DetectionPluginBase):
    manifest = PluginManifest(
        plugin_id="vendor.example_detection",
        name="Example detection rules",
        version="1.0.0",
        capabilities=("detection",),
        mitre_techniques=("T1558.003",),
        required_scopes=("evidence.read",),
        module_kind=ModuleKind.DETECTION,
        read_only=True,
        supports_dry_run=True,
    )

    def detect(
        self,
        context: IntegrationContext,
        observations: list[NormalizedObservation],
    ) -> list[FindingInput]:
        del context
        return [
            FindingInput(
                title="Example rule matched",
                description="A bounded normalized observation matched a defensive rule.",
                severity="medium",
                technique_id="T1558.003",
                evidence={"observation_id": observation.observation_id},
            )
            for observation in observations
            if observation.attributes.get("rule_id")
        ]
```

The concrete repository example is `SafeObservationDetectionPlugin` in `backend/app/plugins/example_detection.py`. It recognizes normalized rule and technique identifiers, bounds text and evidence references, rejects incomplete observations, and emits validated `FindingInput` records. It does not copy raw event payloads into findings.

## Registration and discovery

Built-ins are registered explicitly in `DEFAULT_REGISTRY`. Optional distribution plugins may expose a Python entry point in the `redpath.detection` group, but discovery is **opt-in and allow-listed**:

```python
registry.discover(
    allowed_plugin_ids={"vendor.example_detection"},
    group="redpath.detection",
)
```

The registry sorts candidates deterministically, ignores unlisted entry points without loading them, and reuses the same manifest validation used for built-ins. A discovered plugin must have a valid lower-case plugin ID, a non-empty capability set, `module_kind=detection`, `read_only=True`, `supports_dry_run=True`, and a supported contract version. Duplicate IDs and unsafe manifests fail closed.

Entry-point discovery loads code supplied by the deployment environment. Operators must review and pin the distribution before adding its ID to the allow-list. RedPath does not discover arbitrary packages, run install commands, or accept plugin modules from API clients.

## Input and output rules

`NormalizedObservation` is the only observation boundary. It is tenant-tagged, bounded, schema-validated, and passed through the kernel, which checks that every observation tenant matches the authenticated context before the plugin runs. Plugins should use only allow-listed attributes, cap strings and lists, and place safe evidence references—not raw payloads—inside `FindingInput.evidence`.

A plugin must remain deterministic for the same normalized input, preserve server-derived tenant and actor context, and never treat observation text as executable instructions. `plan()` output is declarative and must contain only the typed `PlannedAction` contract; raw shell commands, arbitrary command arguments, credential material, and destructive operations are prohibited.

## Required tests

Each plugin should have tests for the following cases:

| Test | Required assertion |
| --- | --- |
| Manifest validation | Invalid ID, empty capabilities, unsupported contract, mutating mode, or non-dry-run mode is rejected. |
| Safe plan | The plan is dry-run, read-only, typed, and contains no shell command fields. |
| Positive detection | A valid normalized observation produces a valid `FindingInput` with bounded evidence. |
| Incomplete input | Missing rule or technique context is skipped or produces a safe warning, never an unbounded finding. |
| Tenant isolation | Cross-tenant observations are rejected by the kernel before plugin code receives them. |
| Discovery | Only explicitly allow-listed entry points are loaded; unlisted loaders are not invoked. |
| Failure behavior | Plugin exceptions map to a safe integration error and do not leak raw observations or stack traces. |

Run the focused checks from the repository root with:

```bash
cd backend
python3 -m pytest -q tests/test_detection_plugins.py tests/test_kernel.py tests/test_kernel_extension.py
ruff check app/plugins tests/test_detection_plugins.py
```
