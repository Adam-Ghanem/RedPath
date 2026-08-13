from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import httpx

_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class WazuhIndexerClient:
    """Read-only adapter for the Wazuh indexer alerts index."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_tls: bool = True,
        timeout_seconds: int = 20,
    ) -> None:
        if not base_url.startswith(("https://", "http://")):
            raise ValueError("Wazuh indexer URL must include an HTTP(S) scheme")
        if timeout_seconds < 1 or timeout_seconds > 120:
            raise ValueError("Wazuh timeout must be between 1 and 120 seconds")
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.verify_tls = verify_tls
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def build_search_body(
        *,
        start: datetime,
        end: datetime,
        technique_ids: list[str] | None = None,
        size: int = 200,
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
            filters.append(
                {
                    "bool": {
                        "should": should,
                        "minimum_should_match": 1,
                    }
                }
            )
        return {
            "size": min(max(size, 1), 1000),
            "track_total_hits": False,
            "query": {"bool": {"must": filters}},
            "sort": [{"timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
        }

    async def search_alerts(
        self,
        *,
        start: datetime,
        end: datetime,
        technique_ids: list[str] | None = None,
        size: int = 200,
    ) -> list[dict[str, Any]]:
        body = self.build_search_body(start=start, end=end, technique_ids=technique_ids, size=size)
        async with httpx.AsyncClient(verify=self.verify_tls, timeout=self.timeout_seconds) as client:
            response = await client.post(f"{self.base_url}/wazuh-alerts*/_search", auth=self.auth, json=body)
            response.raise_for_status()
            payload = response.json()
        hits = payload.get("hits", {}).get("hits", []) if isinstance(payload, dict) else []
        return [
            hit.get("_source", {})
            for hit in hits
            if isinstance(hit, dict) and isinstance(hit.get("_source"), dict)
        ]
