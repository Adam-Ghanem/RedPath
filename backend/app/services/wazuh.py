from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from app.services.telemetry_resilience import Checkpoint, CheckpointCodec

_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
ALERTS_INDEX_PATTERN = "wazuh-alerts*"
READ_ONLY_ROLE = "redpath_reader"


class WazuhIndexerClient:
    """Read-only adapter for the Wazuh indexer alerts index."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_tls: bool = True,
        timeout_seconds: int = 20,
        *,
        connector_role: str = READ_ONLY_ROLE,
        read_only: bool = True,
        checkpoint_max_bytes: int = 1024,
    ) -> None:
        self._configuration_error: str | None = None
        if username and password:
            self.validate_configuration(
                base_url=base_url,
                username=username,
                password=password,
                verify_tls=verify_tls,
                timeout_seconds=timeout_seconds,
                connector_role=connector_role,
                read_only=read_only,
            )
        else:
            self._configuration_error = "credentials_missing"
            if not base_url.startswith("https://") or not verify_tls:
                raise ValueError("Wazuh connector requires HTTPS and TLS verification")
            if timeout_seconds < 1 or timeout_seconds > 120:
                raise ValueError("Wazuh timeout must be between 1 and 120 seconds")
            if connector_role != READ_ONLY_ROLE or not read_only:
                raise ValueError("Wazuh connector must remain a read-only redpath_reader")
        if checkpoint_max_bytes < 256 or checkpoint_max_bytes > 16_384:
            raise ValueError("Wazuh checkpoint size is outside the safe range")
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.verify_tls = verify_tls
        self.timeout_seconds = timeout_seconds
        self.connector_role = connector_role
        self.read_only = read_only
        self.checkpoint_max_bytes = checkpoint_max_bytes

    @staticmethod
    def validate_configuration(
        *,
        base_url: str,
        username: str,
        password: str,
        verify_tls: bool,
        timeout_seconds: int,
        connector_role: str = READ_ONLY_ROLE,
        read_only: bool = True,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("Wazuh connector requires HTTPS")
        if not username or not password:
            raise ValueError("Wazuh connector credentials are required server-side")
        if connector_role != READ_ONLY_ROLE:
            raise ValueError("Wazuh connector role must be redpath_reader")
        if not read_only:
            raise ValueError("Wazuh connector must remain read-only")
        if not verify_tls:
            raise ValueError("Wazuh connector TLS verification must remain enabled")
        if timeout_seconds < 1 or timeout_seconds > 120:
            raise ValueError("Wazuh timeout must be between 1 and 120 seconds")

    @staticmethod
    def build_search_body(
        *,
        start: datetime,
        end: datetime,
        technique_ids: list[str] | None = None,
        size: int = 200,
        search_after: list[Any] | None = None,
    ) -> dict[str, Any]:
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("Wazuh query bounds must be timezone-aware")
        start_utc = start.astimezone(timezone.utc)
        end_utc = end.astimezone(timezone.utc)
        if start_utc >= end_utc:
            raise ValueError("Wazuh query start must be before end")
        normalized_techniques = list(dict.fromkeys(technique_ids or []))
        if len(normalized_techniques) > 50 or any(
            not _TECHNIQUE_PATTERN.fullmatch(technique_id) for technique_id in normalized_techniques
        ):
            raise ValueError("Wazuh technique filters must be valid MITRE IDs")
        filters: list[dict[str, Any]] = [
            {
                "range": {
                    "timestamp": {
                        "gte": start_utc.isoformat(),
                        "lte": end_utc.isoformat(),
                    }
                }
            }
        ]
        if normalized_techniques:
            should: list[dict[str, Any]] = []
            for technique_id in normalized_techniques:
                should.extend(
                    [
                        {"term": {"rule.mitre.id": technique_id}},
                        {"match_phrase": {"rule.description": technique_id}},
                    ]
                )
            filters.append({"bool": {"should": should, "minimum_should_match": 1}})
        body: dict[str, Any] = {
            "size": min(max(size, 1), 1000),
            "track_total_hits": False,
            "query": {"bool": {"must": filters}},
            "sort": [{"timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
        }
        if search_after is not None:
            if len(search_after) != 2 or not isinstance(search_after[0], str) or not isinstance(search_after[1], str):
                raise ValueError("Wazuh search_after checkpoint is invalid")
            body["search_after"] = search_after
        return body

    def _assert_configured(self) -> None:
        if self._configuration_error:
            raise ValueError("Wazuh connector is not configured")

    async def search_alerts_page(
        self,
        *,
        start: datetime,
        end: datetime,
        technique_ids: list[str] | None = None,
        size: int = 200,
        checkpoint_cursor: str | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        self._assert_configured()
        search_after: list[Any] | None = None
        if checkpoint_cursor:
            checkpoint = CheckpointCodec.decode(checkpoint_cursor)
            if len(checkpoint_cursor) > self.checkpoint_max_bytes:
                raise ValueError("checkpoint exceeds the configured size limit")
            search_after = [checkpoint.observed_at.isoformat(), checkpoint.provider_id]
        body = self.build_search_body(
            start=start,
            end=end,
            technique_ids=technique_ids,
            size=size,
            search_after=search_after,
        )
        async with httpx.AsyncClient(verify=self.verify_tls, timeout=self.timeout_seconds) as client:
            response = await client.post(f"{self.base_url}/{ALERTS_INDEX_PATTERN}/_search", auth=self.auth, json=body)
            response.raise_for_status()
            payload = response.json()
        hits = payload.get("hits", {}).get("hits", []) if isinstance(payload, dict) else []
        documents: list[dict[str, Any]] = []
        for hit in hits:
            if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
                continue
            provider_id = hit.get("_id")
            if not isinstance(provider_id, str) or not provider_id:
                provider_id = hashlib.sha256(
                    json.dumps(hit["_source"], sort_keys=True, default=str).encode("utf-8")
                ).hexdigest()[:32]
            documents.append({"_id": provider_id[:128], "_source": hit["_source"]})
        next_cursor = None
        if documents:
            last_source = documents[-1]["_source"]
            try:
                observed_at = _parse_provider_timestamp(last_source)
            except ValueError:
                observed_at = None
            if observed_at is not None:
                next_cursor = CheckpointCodec.encode(Checkpoint(observed_at, documents[-1]["_id"]))
        return documents, next_cursor

    async def search_alerts(
        self,
        *,
        start: datetime,
        end: datetime,
        technique_ids: list[str] | None = None,
        size: int = 200,
    ) -> list[dict[str, Any]]:
        documents, _ = await self.search_alerts_page(
            start=start,
            end=end,
            technique_ids=technique_ids,
            size=size,
        )
        return [document["_source"] for document in documents]


def _parse_provider_timestamp(source: dict[str, Any]) -> datetime:
    value = source.get("timestamp") or source.get("@timestamp")
    if not isinstance(value, str):
        raise ValueError("Wazuh hit is missing a valid timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Wazuh hit timestamp is invalid") from exc
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
