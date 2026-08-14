# RedPath Progress

**Updated:** 2026-08-14

## Current state at session start

`PROGRESS.md` did not exist at the start of this session. The repository was on `feat/ai-enterprise-controls`, tracking `origin/feat/ai-enterprise-controls`, at commit `73ce2b7` (`feat: add enterprise AI providers and oversight controls`). The baseline repository evidence is preserved in [`.artifacts/baseline-repository.txt`](.artifacts/baseline-repository.txt) and the raw validation output is preserved in [`.artifacts/baseline-validation.log`](.artifacts/baseline-validation.log).

The baseline suite passed before any new changes:

| Gate | Command | Evidence |
| --- | --- | --- |
| Backend tests | `cd backend && python3 -m pytest -q` | `104 passed, 29 warnings`; exit code `0` |
| Ruff | `cd backend && ruff check .` | `All checks passed!`; exit code `0` |
| Bandit | `cd backend && bandit -q -r app` | exit code `0`; existing comment-parser warnings only |
| Dependency audit | `cd backend && pip-audit -r requirements.txt` | `No known vulnerabilities found`; exit code `0` |
| Frontend install | `cd frontend && npm ci` | `84 packages added; found 0 vulnerabilities`; exit code `0` |
| Frontend tests | `cd frontend && npm run test -- --run` | `5 test files, 16 tests passed`; exit code `0` |
| Frontend build | `cd frontend && npm run build` | Vite build completed; exit code `0`; existing undefined analytics placeholders warned |
| Documentation | `python3 ci/check_docs.py` | `Documentation checks passed`; exit code `0` |

## Priority selected

Only backlog item **1 — Verify Plugin System** was selected. The selection was evidence-based rather than assumed. `backend/app/plugins/base.py` contained only the generic `RedPathPlugin` protocol, `backend/app/plugins/registry.py` used conservative `RegistryPlugin` placeholders, and the existing platform-kernel documentation explicitly described the default adapters as placeholders. The kernel and registry safety envelope was real, but there was no typed `DetectionPlugin` specialization, concrete built-in detection implementation, or entry-point discovery path.

Backlog items 2 through 6 were not started in this session. No partial implementation was left behind for those items.

## Work completed for priority 1

The plugin subsystem now has a concrete, safe detection-plugin lifecycle. `DetectionPlugin` and `DetectionPluginBase` were added to `backend/app/plugins/base.py`. The base class validates normalized observations through the existing kernel boundary, supplies a declarative read-only dry-run plan, and converts plugin output into bounded `IntegrationAnalysis` findings.

`backend/app/plugins/example_detection.py` adds `SafeObservationDetectionPlugin`, registered in `DEFAULT_REGISTRY` as `detection.safe_observation_rules`. It requires a bounded `rule_id` and `technique_id`, validates severity and CVSS values, caps text and evidence references, emits typed `FindingInput` records, and keeps remediation guidance inside the evidence envelope. It does not execute commands, make network calls, or copy raw event payloads into findings.

`PluginRegistry.discover()` was added to `backend/app/plugins/registry.py`. Discovery is explicit and allow-listed through the `redpath.detection` entry-point group. Unlisted entry points are not loaded; loaded entry-point names must match the plugin manifest ID; duplicate, malformed, mutating, or non-dry-run plugins are rejected through the existing registry validation path.

Contributor guidance was added in [`docs/PLUGIN_DEVELOPMENT.md`](docs/PLUGIN_DEVELOPMENT.md), and [`docs/platform-kernel.md`](docs/platform-kernel.md) now distinguishes the generic placeholder adapters from the concrete detection example and allow-listed discovery mechanism.

## Test evidence after the change

The focused plugin and kernel checks passed:

```text
cd backend && python3 -m pytest -q tests/test_detection_plugins.py
7 passed in 0.51s

cd backend && python3 -m pytest -q tests/test_detection_plugins.py tests/test_kernel.py tests/test_kernel_extension.py tests/test_phase2_security.py
31 passed in 10.46s
```

The new `backend/tests/test_detection_plugins.py` covers positive detection, incomplete observations, safe plans, default registry wiring, allow-listed discovery, unsafe manifest rejection, and entry-point identity mismatch. The complete post-change validation output is preserved in [`.artifacts/post-validation.log`](.artifacts/post-validation.log).

## Fresh post-change validation

The full post-change suite completed with every required exit code equal to `0`:

| Gate | Fresh result |
| --- | --- |
| Backend tests | `111 passed, 29 warnings in 29.78s`; exit code `0` |
| Ruff | `All checks passed!`; exit code `0` |
| Bandit | exit code `0`; comment-parser warnings only |
| pip-audit | `No known vulnerabilities found`; exit code `0` |
| `npm ci` | `84 packages added; found 0 vulnerabilities`; exit code `0` |
| Frontend tests | `5 test files, 16 tests passed`; exit code `0` |
| Frontend build | Vite build completed; exit code `0` |
| Documentation checks | `Documentation checks passed`; exit code `0` |

The frontend build still emits the pre-existing warnings that `VITE_ANALYTICS_ENDPOINT` and `VITE_ANALYTICS_WEBSITE_ID` are undefined and that the analytics script lacks `type="module"`. These warnings did not fail the build and were not changed because they are unrelated to the selected plugin priority.

## Commit and remaining work

The plugin upgrade and this progress record are committed in the next commit on the current feature branch. Backlog items 2 through 6 remain explicitly open: the flaky-retention 10-run investigation, load/concurrency benchmarks, new Semgrep/gitleaks/Hypothesis security pass, additional null-provider edge cases, and README consolidation. They must be selected one at a time in a later session and validated with fresh evidence before being marked complete.


## Model-tier upgrade — 2026-08-14

This follow-up was implemented on branch `feat/ai-model-tiers`, based on the existing `feat/ai-enterprise-controls` work. A live model catalog was captured in [`.artifacts/live-llm-model-catalog.json`](.artifacts/live-llm-model-catalog.json). It listed `claude-haiku-4-5`, `claude-sonnet-4-6`, `claude-opus-4-6`, and `claude-opus-4-7`; it did **not** list `claude-sonnet-5`. The implementation therefore uses the verified `claude-sonnet-4-6` identifier for the deep tier rather than configuring an unavailable model name.

`Settings` now supports explicit `anthropic_model_fast` and `anthropic_model_deep` fields, independent timeout and token budgets, and `ai_deep_requests_per_minute`. The legacy `anthropic_model` setting remains accepted as a backward-compatible alias and emits a deprecation warning when explicitly used without an explicit fast model. `AnthropicProvider.generate()` accepts `model_tier="fast"|"deep"`, risk scoring selects `fast`, and copilot selects `deep`. Copilot retains its existing limiter and additionally uses a stricter deep-tier limiter. The selected tier is included in the redacted AI audit response summary.

The evaluation harness is now present at [`backend/tests/ai_eval/golden.py`](backend/tests/ai_eval/golden.py) and [`backend/tests/ai_eval/run_comparison.py`](backend/tests/ai_eval/run_comparison.py). The same 20 synthetic scenarios were run through the live OpenAI-compatible built-in proxy using `claude-haiku-4-5` and `claude-sonnet-4-6`. The exact result is preserved in [`.artifacts/ai-model-comparison.json`](.artifacts/ai-model-comparison.json), and the interpretation is documented in [`docs/AI_MODEL_COMPARISON.md`](docs/AI_MODEL_COMPARISON.md).

| Measured gate | Haiku fast | Sonnet deep | Evidence |
| --- | ---: | ---: | --- |
| Tier agreement | `19/20 = 95%` | `20/20 = 100%` | `.artifacts/ai-model-comparison.json` |
| Valid MITRE technique output | `20/20 = 100%` | `20/20 = 100%` | Same artifact |
| Evidence-term grounding check | `20/20 = 100%` | `20/20 = 100%` | Same artifact |
| Latency p50 | `2369.39 ms` | `3853.69 ms` | Same artifact |
| Latency p95 | `5441.84 ms` | `4652.27 ms` | Same artifact |
| Estimated evaluation cost | `$0.014430` | `$0.048990` | Same artifact |

The evidence demonstrates a narrow measured quality gain in deterministic-tier agreement (+5 percentage points), while the technique-validity and bounded grounding checks were already at ceiling for both models. Deep was therefore restricted to copilot reasoning instead of being applied globally. The comparison used the built-in proxy rather than direct production Anthropic billing, so it is a quality/routing signal and not a production SLA or billing claim.

Focused validation after the tier changes: `16 passed, 5 warnings` for `backend/tests/test_ai_features.py`; `compileall` passed; Ruff reported `All checks passed!`. The new tests cover risk fast-tier routing, copilot deep-tier routing, tier-specific Anthropic model/budget/timeout payloads, legacy alias warning, independent deep limiter behavior, and none-provider fallback independence.

The previous uncommitted schema additions for the not-yet-finished narrative/gap/remediation feature work were preserved in this branch but were not implemented or claimed as part of this model-tier task. The remaining limitation is that the current evaluator’s grounding metric is bounded and synthetic; it should be strengthened with analyst-reviewed reference answers before making a broader model-selection decision.


### Final validation for model-tier branch

The final validation was rerun after the audit-tier regression test was added. Raw output is preserved in [`.artifacts/model-tier-validation.log`](.artifacts/model-tier-validation.log).

| Gate | Fresh final result |
| --- | --- |
| Backend tests | `116 passed, 30 warnings in 31.37s`; exit code `0` |
| Ruff | `All checks passed!`; exit code `0` |
| Bandit | exit code `0`; existing comment-parser warnings only |
| pip-audit | `No known vulnerabilities found`; exit code `0` |
| `npm ci` | `found 0 vulnerabilities`; exit code `0` |
| Frontend tests | exit code `0` |
| Frontend build | Vite build completed; exit code `0` |
| Documentation checks | `Documentation checks passed`; exit code `0` |
| Overall script status | `VALIDATION_STATUS: 0` |

The frontend build retained the pre-existing undefined analytics-variable and script-type warnings; no unrelated frontend changes were made.
