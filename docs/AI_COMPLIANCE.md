# RedPath AI Compliance Guide

## Operating modes

RedPath supports three explicit provider modes. The default is `AI_FEATURES_ENABLED=false` with `AI_PROVIDER=none`, which performs deterministic, rule-based explanations only and makes no model request. `AI_PROVIDER=local` sends bounded redacted context to an operator-controlled Ollama or vLLM-compatible HTTP endpoint. `AI_PROVIDER=anthropic` sends the same redacted projection to the configured Anthropic Messages API and requires `ANTHROPIC_API_KEY` from an environment variable or secret manager.

| Mode | External network call | API key | Explanation source | Recommended use |
| --- | --- | --- | --- | --- |
| `none` | None | None | Deterministic graph, risk, and MITRE rules | Strict no-AI environments and CI |
| `local` | Only to the configured operator-owned endpoint | None in RedPath | Self-hosted model | Data residency or air-gapped deployments |
| `anthropic` | Anthropic API only | Environment-only | External model plus deterministic constraints | Deployments that approve external processing |

Provider selection is server-side. Clients cannot select a provider through a request body, and no arbitrary URL or shell command is accepted through the API.

## Data flow and redaction

```text
Authorized finding/path
        |
        v
Tenant + RBAC check
        |
        v
Bounded context projection
        |
        v
Redaction: secrets, credentials, auth values, raw payloads, IP addresses
        |
        +--> SHA-256 context hash + provider/endpoint/latency/status --> AI audit log
        |
        v
Provider selected by server config
  none       local HTTP endpoint       Anthropic Messages API
        \            |                         /
         \           |                        /
          +----------+-----------------------+
                     |
                     v
        Schema validation + deterministic constraints
                     |
                     v
       AI-generated — verify before acting
```

An illustrative redacted projection may contain:

```json
{
  "title": "Service identity exposure",
  "severity": "high",
  "asset_id": "asset-[REDACTED]",
  "technique_id": "T1558.003",
  "description": "A service principal mapping requires analyst review.",
  "evidence": "password=[REDACTED], source=[REDACTED], client=[IP_REDACTED]"
}
```

RedPath does not send credentials, password values, tokens, authorization headers, raw packet or event payload fields, or IP addresses to a model provider. The AI audit log stores a hash of the redacted context and the field categories included, not the raw prompt or context.

## Self-hosted setup

For a local deployment, configure an operator-owned endpoint and model:

```dotenv
AI_FEATURES_ENABLED=true
AI_PROVIDER=local
LOCAL_LLM_BASE_URL=http://127.0.0.1:11434/api/generate
LOCAL_LLM_MODEL=llama3.1:8b
LOCAL_LLM_TIMEOUT_SECONDS=30
```

The local endpoint must be reachable from the backend container or host and should be protected by the deployment’s network controls. RedPath does not install, start, or manage Ollama/vLLM, does not accept arbitrary provider URLs from clients, and does not send an API key in local mode. For vLLM deployments that expose an OpenAI-compatible route, place a small approved adapter in front of the endpoint or configure a compatible response shape containing `choices[0].message.content`.

For Anthropic mode:

```dotenv
AI_FEATURES_ENABLED=true
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=<deployment-secret>
ANTHROPIC_MODEL_FAST=claude-haiku-4-5
ANTHROPIC_MODEL_DEEP=claude-sonnet-4-6
ANTHROPIC_TIMEOUT_SECONDS_FAST=15
ANTHROPIC_TIMEOUT_SECONDS_DEEP=30
ANTHROPIC_MAX_TOKENS_FAST=1200
ANTHROPIC_MAX_TOKENS_DEEP=2400
```

Never commit the key or place it in a request body, URL, audit event, or frontend bundle.

## Audit review

Every risk or copilot invocation creates an `ai.call` event, including `none` mode and provider failures. The separate append-only JSONL stream is configured with `AI_AUDIT_LOG_PATH` and contains the timestamp, authenticated actor, tenant, endpoint, provider, context hash, included field categories, redaction profile, response summary, latency, success state, and safe error type when applicable. Human feedback creates an `ai.feedback` event containing the source reference, verdict, actor, and a hash of analyst notes.

Users with the existing `view_audit` permission can review their tenant’s recent records through:

```text
GET /api/v1/ai/audit-log?limit=100
```

The endpoint never returns another tenant’s events and never returns raw prompts or analyst notes. `POST /api/v1/ai/feedback` accepts `confirmed` or `incorrect` and records the authenticated actor server-side:

```json
{
  "source_type": "attack_path",
  "source_id": "path-abc123",
  "verdict": "confirmed",
  "notes": "Analyst verified the evidence references and modeled priority."
}
```

## Human verification policy

The deterministic graph and risk engine remain authoritative. AI output is advisory and is returned with `requires_human_review=true` whenever the deterministic tier is high or critical, the provider tier differs from the centrality-derived tier by more than one level, provider confidence is absent or below `0.6`, or AI is disabled/unavailable. The frontend displays **AI-generated — verify before acting** alongside AI explanation surfaces. Analysts can record a confirmation or correction through the feedback endpoint; feedback does not automatically change risk scores or remediation state.

## Retention and integrity

AI audit retention is controlled by `AI_AUDIT_RETENTION_DAYS` and `AI_AUDIT_MAX_ENTRIES`; the defaults are 365 days and 10,000 returned entries. Retention is applied when reading the review view so the append-only source remains intact for integrity verification and external archival. Operators should archive or delete the underlying file according to their approved records schedule and access policy. The audit stream uses the same chained digest pattern as the core audit log, and raw prompt data is intentionally unavailable for later recovery.


## Model tiers and measured comparison

Anthropic-backed calls now use two server-selected tiers. Risk scoring uses the fast tier because it is latency-sensitive and the deterministic risk engine remains authoritative. Copilot explanations use the deep tier because they are analyst-facing and require more contextual reasoning. `AI_PROVIDER=none` bypasses both model tiers and keeps the deterministic fallbacks unchanged.

| Endpoint/use | Tier | Default verified model | Timeout | Max output tokens | Rate control |
| --- | --- | --- | ---: | ---: | ---: |
| `POST /api/v1/risk/ai-assess` | `fast` | `claude-haiku-4-5` | 15 s | 1,200 | General AI limiter |
| `POST /api/v1/copilot/explain` | `deep` | `claude-sonnet-4-6` | 30 s | 2,400 | General copilot limiter plus deep limiter: 5/min by default |

The requested `claude-sonnet-5` identifier was not present in the live model catalog captured on 2026-08-14. The implementation therefore uses the verified available `claude-sonnet-4-6` identifier rather than configuring an unverified model name. The captured catalog and pricing evidence are in `.artifacts/live-llm-model-catalog.json`.

The comparison harness is `backend/tests/ai_eval/run_comparison.py` and uses the same 20 synthetic scenarios for both models through the OpenAI-compatible built-in proxy. It is not a direct Anthropic billing run, so the result is a model-quality and routing signal rather than a production SLA guarantee. The exact artifact is `.artifacts/ai-model-comparison.json`.

| Metric | Fast: `claude-haiku-4-5` | Deep: `claude-sonnet-4-6` | Observed change |
| --- | ---: | ---: | ---: |
| Tier agreement with deterministic engine | 19/20 = 95% | 20/20 = 100% | +5 percentage points |
| Valid MITRE technique output | 20/20 = 100% | 20/20 = 100% | No change; ceiling reached |
| Evidence-term grounding check | 20/20 = 100% | 20/20 = 100% | No change; ceiling reached |
| Latency p50 | 2,369.39 ms | 3,853.69 ms | +1,484.30 ms |
| Latency p95 | 5,441.84 ms | 4,652.27 ms | -789.57 ms in this run |
| Estimated run cost | $0.014430 | $0.048990 | 3.40× higher |

The evidence supports a narrow upgrade decision: deep tiering improved deterministic-tier agreement on this 20-case run, while technique validity and the bounded evidence-term check were already at 100%. The higher cost and p50 latency justify keeping the deep tier restricted to copilot-style reasoning rather than applying it to all endpoints. These results do not prove universal model superiority; future changes to prompts, model versions, or production traffic require another evaluation run.
