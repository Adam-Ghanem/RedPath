from __future__ import annotations

from typing import Any

from app.plugins.base import PluginManifest

BUILTIN_PLUGINS: tuple[PluginManifest, ...] = (
    PluginManifest(
        plugin_id="recon.safe_inventory",
        name="Safe service inventory",
        version="0.1.0",
        capabilities=("recon", "asset_discovery"),
        mitre_techniques=(),
        supports_dry_run=True,
    ),
    PluginManifest(
        plugin_id="ad.observation_analyzer",
        name="AD observation analyzer",
        version="0.1.0",
        capabilities=("detection", "finding_correlation"),
        mitre_techniques=("T1558.003", "T1558.004", "T1649"),
        supports_dry_run=True,
    ),
    PluginManifest(
        plugin_id="purple.wazuh_gap_report",
        name="Wazuh detection-gap report",
        version="0.1.0",
        capabilities=("purple_team", "siem_validation"),
        mitre_techniques=("T1558.003", "T1558.004", "T1649"),
        supports_dry_run=True,
    ),
)


def list_plugins() -> list[dict[str, Any]]:
    return [
        {
            "plugin_id": plugin.plugin_id,
            "name": plugin.name,
            "version": plugin.version,
            "capabilities": list(plugin.capabilities),
            "mitre_techniques": list(plugin.mitre_techniques),
            "supports_dry_run": plugin.supports_dry_run,
        }
        for plugin in BUILTIN_PLUGINS
    ]
