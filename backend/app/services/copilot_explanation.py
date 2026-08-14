from __future__ import annotations

import hashlib
import json
import re
from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Any, Protocol

import httpx

from app.core.config import Settings
from app.schemas.contracts import (
    CopilotExplainRequest,
    CopilotExplanationResponse,
    CopilotProviderOutput,
)


class ProviderUnavailable(Exception):
    """The optional provider is not configured or cannot be reached."""


class ProviderTimeout(Exception):
    """The optional provider exceeded its bounded timeout."""


class ProviderRateLimited(Exception):
    """The optional provider returned a rate-limit response."""


class ExplanationProvider(Protocol):
    def explain(self, context: dict[str, Any]) -> CopilotProviderOutput:
        """Return a structured explanation for minimized context only."""


class OpenAICompatibleProvider:
    """Small provider adapter; the API key is read from settings populated by env only."""

    def __init__(self, *, api_base: str, api_key: str, model: str, timeout_seconds: int) -> None:
        self._api_base = api_base.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._timeout_seconds = timeout_seconds

    def explain(self, context: dict[str, Any]) -> CopilotProviderOutput:
        if not self._api_base or not self._api_key:
            raise ProviderUnavailable("provider is not configured")
        payload = {
            "model": self._model,
            "temperature": 0,
            "max_completion_tokens": 500,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a defensive SOC explanation assistant. Use only the sanitized context. "
                        "Do not invent facts, identities, hosts, causes, or actions outside the context. "
                        "Return JSON with explanation, next_actions (one or two strings), and confidence_note. "
                        "The explanation must be concise and explicitly state that unprovided facts cannot be asserted."
                    ),
                },
                {"role": "user", "content": json.dumps(context, sort_keys=True, separators=(",", ":"))},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "copilot_explanation",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "explanation": {"type": "string", "maxLength": 1200},
                            "next_actions": {
                                "type": "array",
                                "items": {"type": "string", "maxLength": 256},
                                "minItems": 1,
                                "maxItems": 2,
                            },
                            "confidence_note": {"type": "string", "maxLength": 512},
                        },
                        "required": ["explanation", "next_actions", "confidence_note"],
                        "additionalProperties": False,
                    },
                },
            },
        }
        try:
            response = httpx.post(
                f"{self._api_base}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json=payload,
                timeout=self._timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise ProviderTimeout("provider request timed out") from exc
        except httpx.HTTPError as exc:
            raise ProviderUnavailable("provider request failed") from exc
        if response.status_code == 429:
            raise ProviderRateLimited("provider rate limited the request")
        if response.status_code >= 400:
            raise ProviderUnavailable("provider returned an error")
        try:
            content = response.json()["choices"][0]["message"]["content"]
            return CopilotProviderOutput.model_validate_json(content)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ValueError("provider returned invalid structured output") from exc


@dataclass(frozen=True)
class _CacheEntry:
    expires_at: float
    response: CopilotExplanationResponse


class _TenantResultCache:
    def __init__(self, *, ttl_seconds: int, max_entries: int) -> None:
        self._ttl_seconds = max(1, ttl_seconds)
        self._max_entries = max(1, max_entries)
        self._items: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = Lock()

    def get(self, key: str) -> CopilotExplanationResponse | None:
        now = monotonic()
        with self._lock:
            entry = self._items.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._items.pop(key, None)
                return None
            self._items.move_to_end(key)
            return deepcopy(entry.response)

    def put(self, key: str, response: CopilotExplanationResponse) -> None:
        with self._lock:
            self._items[key] = _CacheEntry(monotonic() + self._ttl_seconds, deepcopy(response))
            self._items.move_to_end(key)
            while len(self._items) > self._max_entries:
                self._items.popitem(last=False)


_SENSITIVE_FIELD_PATTERN = re.compile(
    r"(?i)\b(?:asset_id|asset_ids|hostname|host|user|username|account|principal|evidence_id|evidence_ids|ip|address|mac)\b\s*[:=]\s*[^\s,;]+"
)
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)\b(?:asset_id|asset_ids|hostname|host|user|username|account|principal|evidence_id|evidence_ids|ip|address|mac)\b"
)
_SAFE_BASIS_WORDS = {
    "access",
    "alert",
    "cloud",
    "configuration",
    "credential",
    "detected",
    "detection",
    "evidence",
    "gap",
    "identity",
    "lateral",
    "matched",
    "movement",
    "observed",
    "privilege",
    "rule",
    "service",
    "signal",
    "technique",
}


class CopilotExplanationService:
    """Optional AI explanation around deterministic, tenant-authorized risk results."""

    def __init__(
        self,
        settings: Settings,
        *,
        provider: ExplanationProvider | None = None,
    ) -> None:
        self._settings = settings
        self._provider = provider or self._default_provider(settings)
        self._cache = _TenantResultCache(
            ttl_seconds=settings.ai_cache_ttl_seconds,
            max_entries=settings.ai_cache_max_entries,
        )

    @staticmethod
    def _default_provider(settings: Settings) -> ExplanationProvider | None:
        if settings.ai_provider != "openai_compatible":
            return None
        if not settings.ai_api_key or not settings.ai_api_base:
            return None
        return OpenAICompatibleProvider(
            api_base=settings.ai_api_base,
            api_key=settings.ai_api_key,
            model=settings.ai_model,
            timeout_seconds=settings.ai_request_timeout_seconds,
        )

    @staticmethod
    def _tier(score: float, centrality: float, deterministic_tier: str) -> str:
        tiers = ["low", "medium", "high", "critical"]
        score_tier = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
        tier = max(tiers.index(deterministic_tier), tiers.index(score_tier))
        if centrality >= 0.8 and score >= 60:
            tier = min(len(tiers) - 1, tier + 1)
        return tiers[tier]

    @staticmethod
    def _redact_text(value: str, limit: int) -> str:
        text = value[:limit]
        text = re.sub(
            r"(?i)\b(?:authorization|bearer|basic|password|passwd|secret|token|api[-_]?key)\b\s*[:=]\s*[^\s,;]+",
            "[REDACTED]",
            text,
        )
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_IP]", text)
        text = _SENSITIVE_FIELD_PATTERN.sub("[REDACTED_FIELD]", text)
        text = _SENSITIVE_KEY_PATTERN.sub("[REDACTED_FIELD]", text)
        text = re.sub(
            r"(?i)\b(?:host|hostname|user|username|account|asset)\s*[:=]\s*[A-Za-z0-9._:-]+",
            "[REDACTED_IDENTIFIER]",
            text,
        )
        text = re.sub(r"\b[A-Za-z0-9_-]+\.(?:local|lab|internal|corp|example|com)\b", "[REDACTED_HOST]", text)
        return text

    @classmethod
    def _safe_evidence_basis(cls, value: str) -> str:
        techniques = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", value)
        words = [word for word in re.findall(r"[A-Za-z][A-Za-z_-]{2,24}", value.lower()) if word in _SAFE_BASIS_WORDS]
        safe_tokens = list(dict.fromkeys(techniques + words))
        return " ".join(safe_tokens[:16]) or "sanitized evidence signal"

    @classmethod
    def _minimized_context(cls, request: CopilotExplainRequest) -> dict[str, Any]:
        path = request.attack_path
        context: dict[str, Any] = {
            "subject_type": request.subject_type,
            "deterministic_score": round(request.deterministic_score, 4),
            "centrality": round(request.centrality, 4),
            "deterministic_tier": request.deterministic_tier,
            "evidence": [
                {
                    "severity": evidence.severity,
                    "technique_id": evidence.technique_id,
                    "signal": cls._safe_evidence_basis(evidence.signal),
                }
                for evidence in request.evidence
            ],
        }
        if path is not None:
            context["attack_path"] = {
                "risk_score": round(path.risk_score, 4),
                "centrality": round(path.centrality, 4),
                "hop_count": path.hop_count,
                "asset_count": path.asset_count,
                "evidence_count": path.evidence_count,
                "technique_ids": path.technique_ids,
                "rationale": cls._safe_evidence_basis(path.rationale),
            }
        return context

    @staticmethod
    def _context_hash(tenant_id: str, context: dict[str, Any]) -> str:
        encoded = json.dumps(
            {"tenant_id": tenant_id, "context": context}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _fallback_text(request: CopilotExplainRequest, tier: str) -> tuple[str, list[str], str]:
        explanation = (
            f"The deterministic risk tier is {tier} at {request.deterministic_score:.1f}/100. "
            "This result uses only the supplied sanitized score, centrality, and bounded evidence.\n\n"
            "No additional facts can be asserted without supporting evidence in the request."
        )
        actions = [
            "Review the bounded evidence and confirm the deterministic priority in the authorized case workflow.",
            "Apply or test the existing defensive control associated with the modeled finding or path.",
        ]
        confidence = "Deterministic-only fallback; no model output was used, and unprovided facts cannot be asserted."
        return explanation, actions, confidence

    @staticmethod
    def _validate_references(
        request: CopilotExplainRequest,
        *,
        authorized_asset_ids: set[str] | None,
        authorized_evidence_ids: set[str] | None,
    ) -> None:
        if request.subject_type == "attack_path" and request.attack_path is None:
            raise ValueError("attack_path context is required for an attack_path subject")
        path = request.attack_path
        requested_assets = set(path.asset_ids if path else [])
        requested_evidence = set(path.evidence_ids if path else [])
        requested_evidence.update(evidence.evidence_id for evidence in request.evidence)
        if request.subject_type == "attack_path" and not (requested_assets or requested_evidence):
            raise PermissionError("AI assessment requires a tenant-authorized asset or evidence reference")
        if authorized_asset_ids is not None and not requested_assets <= authorized_asset_ids:
            raise PermissionError("AI assessment references assets outside the authenticated tenant")
        if authorized_evidence_ids is not None and not requested_evidence <= authorized_evidence_ids:
            raise PermissionError("AI assessment references evidence outside the authenticated tenant")

    def explain(
        self,
        request: CopilotExplainRequest,
        *,
        authorized_tenant_id: str,
        authorized_asset_ids: set[str] | None = None,
        authorized_evidence_ids: set[str] | None = None,
    ) -> CopilotExplanationResponse:
        self._validate_references(
            request,
            authorized_asset_ids=authorized_asset_ids,
            authorized_evidence_ids=authorized_evidence_ids,
        )
        context = self._minimized_context(request)
        context_hash = self._context_hash(authorized_tenant_id, context)
        cached = self._cache.get(context_hash)
        if cached is not None:
            return cached.model_copy(update={"cache_hit": True})
        tier = self._tier(request.deterministic_score, request.centrality, request.deterministic_tier)
        explanation, actions, confidence = self._fallback_text(request, tier)
        ai_status = "disabled"
        fallback_reason = "ai_disabled"
        data_egress = "none"
        if self._settings.ai_features_enabled and self._provider is None:
            ai_status = "fallback"
            fallback_reason = "provider_unavailable"
        elif self._settings.ai_features_enabled and self._provider is not None:
            try:
                provider_output = self._provider.explain(context)
                explanation = self._redact_text(provider_output.explanation, 1200)
                explanation = "\n\n".join(explanation.split("\n\n")[:3])
                actions = [self._redact_text(action, 256) for action in provider_output.next_actions[:2]]
                confidence = self._redact_text(provider_output.confidence_note, 512)
                ai_status = "generated"
                fallback_reason = "none"
                data_egress = "sanitized_context_only"
            except ProviderTimeout:
                fallback_reason = "provider_timeout"
            except ProviderRateLimited:
                fallback_reason = "provider_rate_limited"
            except ProviderUnavailable:
                fallback_reason = "provider_unavailable"
            except ValueError:
                fallback_reason = "provider_invalid_output"
            except Exception:
                fallback_reason = "provider_error"
            if ai_status != "generated":
                ai_status = "fallback"
        response = CopilotExplanationResponse(
            tenant_id=authorized_tenant_id,
            subject_type=request.subject_type,
            subject_id=request.subject_id,
            deterministic_score=request.deterministic_score,
            deterministic_tier=request.deterministic_tier,
            tier=tier,
            explanation=explanation,
            next_actions=actions,
            confidence_note=confidence,
            ai_status=ai_status,
            fallback_reason=fallback_reason,
            context_sha256=context_hash,
            data_egress=data_egress,
            cache_hit=False,
        )
        self._cache.put(context_hash, response)
        return response


def build_copilot_service(
    settings: Settings, *, provider: ExplanationProvider | None = None
) -> CopilotExplanationService:
    return CopilotExplanationService(settings, provider=provider)
