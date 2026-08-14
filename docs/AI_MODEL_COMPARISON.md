# RedPath AI Model Comparison

**Run date:** 2026-08-14  
**Dataset:** 20 synthetic, redacted attack-path scenarios in [`backend/tests/ai_eval/golden.py`](../backend/tests/ai_eval/golden.py)  
**Artifact:** [`../.artifacts/ai-model-comparison.json`](../.artifacts/ai-model-comparison.json)  
**Evaluator:** [`backend/tests/ai_eval/run_comparison.py`](../backend/tests/ai_eval/run_comparison.py)

## Decision context

The previous RedPath configuration selected one Anthropic model for every AI endpoint. That made the latency-sensitive risk-scoring path pay the same model cost as analyst-facing explanations. The new strategy uses `claude-haiku-4-5` for risk scoring and the verified available `claude-sonnet-4-6` for copilot explanations.

The requested `claude-sonnet-5` identifier was not present in the live model catalog captured on the run date. The implementation does not configure an unverified model identifier; it uses `claude-sonnet-4-6`, whose availability and pricing were captured in [`.artifacts/live-llm-model-catalog.json`](../.artifacts/live-llm-model-catalog.json). This is a deliberate compatibility decision, not an assumption that Sonnet 5 exists in the configured provider catalog.

## Methodology

The evaluator sent the same 20 scenarios to both models through the OpenAI-compatible built-in proxy using the same system prompt, response schema, maximum output budget, and order-independent scenario data. The prompt included a risk score, allowed MITRE technique IDs, evidence terms, and the scenario statement; it did **not** disclose the expected tier label. Each response was parsed as JSON after normalizing the provider’s fenced-JSON presentation.

The evaluator records three quality checks. **Tier agreement** compares the returned tier with the deterministic expected tier. **Technique validity** requires every returned technique ID to be one of the scenario’s allowed MITRE IDs. **Evidence-term grounding** requires the explanation to contain at least one of the scenario’s evidence terms. These are bounded automated checks, not a substitute for analyst review or a claim of universal factual correctness.

## Measured results

| Metric | Fast: `claude-haiku-4-5` | Deep: `claude-sonnet-4-6` | Difference |
| --- | ---: | ---: | ---: |
| Tier agreement | 19/20 = **95.00%** | 20/20 = **100.00%** | **+5.00 pp** |
| Valid MITRE technique output | 20/20 = **100.00%** | 20/20 = **100.00%** | 0 pp; ceiling reached |
| Evidence-term grounding check | 20/20 = **100.00%** | 20/20 = **100.00%** | 0 pp; ceiling reached |
| Prompt tokens | 2,530 | 2,550 | +20 |
| Completion tokens | 2,380 | 2,756 | +376 |
| Estimated run cost | **$0.014430** | **$0.048990** | **3.40×** |
| Latency mean | 2,890.74 ms | 3,730.21 ms | +839.47 ms |
| Latency p50 | **2,369.39 ms** | **3,853.69 ms** | +1,484.30 ms |
| Latency p95 | 5,441.84 ms | 4,652.27 ms | -789.57 ms in this run |
| Latency p99 | 5,441.84 ms | 4,652.27 ms | -789.57 ms in this run |

The run therefore provides a **narrow measured quality gain**: tier agreement improved by five percentage points. The two other automated checks were already at 100% on the fast model, so this dataset does not demonstrate a technique-validity or evidence-term-grounding improvement. The deep model generated more output tokens and cost approximately 3.40 times as much for this run.

## Redacted before/after examples

The following excerpts contain only synthetic scenario text and public MITRE IDs. They are shortened from the saved artifact and contain no tenant data, credentials, IP addresses, or raw events.

| Scenario | Fast model excerpt | Deep model excerpt | Measured result |
| --- | --- | --- | --- |
| `ticket-medium` | “A service ticket exposure on a non-critical workstation with limited downstream impact presents minimal risk.” The model returned `low`. | “A risk score of 50/100 places this event at a medium tier… the limited blast radius and non-critical asset classification prevent elevation to high or critical tiers.” The model returned `medium`. | Deep matched the deterministic `medium`; fast did not. |
| `kerberoast-critical-2` | “A service ticket followed by admin-share access to tier-0 control represents a critical privilege escalation pathway.” | “A risk score of 95/100 combined with evidence of a service ticket request followed by lateral movement via an admin share directly to a tier-0 asset represents a critical threat.” | Both matched `critical`; both returned only allowed techniques. |

## Operational controls

The implementation routes `POST /api/v1/risk/ai-assess` through `model_tier="fast"` and routes `POST /api/v1/copilot/explain` through `model_tier="deep"`. The deep path has a separate default limiter of five requests per minute, in addition to the existing copilot limiter. Fast and deep calls have independent default timeout and maximum-token budgets: 15 seconds and 1,200 tokens for fast, versus 30 seconds and 2,400 tokens for deep. Every audit event records the selected `model_tier` in its redacted response summary.

The legacy `ANTHROPIC_MODEL` setting remains accepted for backward compatibility. When it is explicitly supplied without an explicit fast model, `Settings.model_for_tier()` emits a deprecation warning and uses the legacy value. New deployments should set `ANTHROPIC_MODEL_FAST` and `ANTHROPIC_MODEL_DEEP` explicitly.

## Limitations and interpretation

This comparison used the OpenAI-compatible built-in proxy with the same model IDs, not a live request through an operator’s direct Anthropic API endpoint. The token-derived cost is an estimate using the live catalog prices captured at run time; it is not a billing statement. The dataset contains 20 synthetic cases and uses bounded automated grounding checks. It does not establish production latency, production quality, or universal superiority. Any model identifier or prompt change should trigger a fresh evaluation run before changing the tier assignment.
