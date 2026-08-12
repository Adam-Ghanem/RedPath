from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class PluginManifest:
    plugin_id: str
    name: str
    version: str
    capabilities: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    supports_dry_run: bool = True


class RedPathPlugin(Protocol):
    manifest: PluginManifest

    def plan(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        ...

    def analyze(self, observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ...
