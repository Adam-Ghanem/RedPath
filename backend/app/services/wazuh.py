from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx


class WazuhIndexerClient:
    """Read-only adapter for the Wazuh indexer alerts index."""

    def __init__(self, base_url: str, username: str, password: str, verify_tls: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password)
        self.verify_tls = verify_tls

    async def search_alerts(
        self,
        *,
        start: datetime,
        end: datetime,
        technique_ids: list[str] | None = None,
        size: int = 200,
    ) -> list[dict[str, Any]]:
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("Wazuh query bounds must be timezone-aware")
        if start >= end:
            raise ValueError("Wazuh query start must be before end")
        must: list[dict[str, Any]] = [
            {
                "range": {
                    "timestamp": {
                        "gte": start.astimezone(timezone.utc).isoformat(),
                        "lte": end.astimezone(timezone.utc).isoformat(),
                    }
                }
            }
        ]
        if technique_ids:
            must.append({"query_string": {"query": " OR ".join(technique_ids)}})
        body = {
            "size": min(max(size, 1), 1000),
            "query": {"bool": {"must": must}},
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        async with httpx.AsyncClient(verify=self.verify_tls, timeout=20) as client:
            response = await client.post(f"{self.base_url}/wazuh-alerts*/_search", auth=self.auth, json=body)
            response.raise_for_status()
            payload = response.json()
        return [hit.get("_source", {}) for hit in payload.get("hits", {}).get("hits", [])]
