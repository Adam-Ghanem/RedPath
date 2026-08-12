from __future__ import annotations

import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass

from app.core.scope import ScopePolicy
from app.schemas.contracts import AssetObservation, ReconCommand, ReconResult


@dataclass(frozen=True)
class CommandSpec:
    tool: str
    purpose: str
    argv_builder: object


class ReconService:
    """Safe discovery orchestration for explicitly allow-listed lab IPs."""

    def __init__(self, scope: ScopePolicy, timeout_seconds: int = 30) -> None:
        self.scope = scope
        self.timeout_seconds = timeout_seconds

    def plan(self, targets: list[str], profile: str = "safe") -> list[ReconCommand]:
        validated = self.scope.validate_targets(targets)
        commands: list[ReconCommand] = []
        for target in validated:
            commands.append(
                ReconCommand(
                    tool="nmap",
                    argv=["nmap", "-sT", "-Pn", "--top-ports", "100", "--open", "-T2", target],
                    purpose="Inventory common TCP services without exploit scripts.",
                )
            )
            if profile == "service_inventory":
                commands.append(
                    ReconCommand(
                        tool="enum4linux",
                        argv=["enum4linux", "-a", target],
                        purpose="Collect SMB/Windows identity metadata in the lab.",
                    )
                )
                commands.append(
                    ReconCommand(
                        tool="smbclient",
                        argv=["smbclient", "-L", f"//{target}", "-N", "--no-pass"],
                        purpose="List anonymously visible SMB shares without credentials.",
                    )
                )
        return commands

    def run(self, targets: list[str], profile: str = "safe", dry_run: bool = True) -> ReconResult:
        commands = self.plan(targets, profile)
        warnings: list[str] = []
        assets: list[AssetObservation] = []
        if dry_run:
            warnings.append("Dry-run enabled: no network command was executed.")
            return ReconResult(
                scan_id=str(uuid.uuid4()),
                dry_run=True,
                targets=self.scope.validate_targets(targets),
                commands=commands,
                warnings=warnings,
            )

        for command in commands:
            if shutil.which(command.tool) is None:
                warnings.append(f"Tool unavailable; skipped: {command.tool}")
                continue
            try:
                completed = subprocess.run(
                    command.argv,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                command.executed = True
                if command.tool == "nmap":
                    assets.extend(self._parse_nmap(command.argv[-1], completed.stdout))
                if completed.returncode != 0:
                    warnings.append(f"{command.tool} exited with code {completed.returncode}")
            except subprocess.TimeoutExpired:
                warnings.append(f"{command.tool} timed out after {self.timeout_seconds}s")
        return ReconResult(
            scan_id=str(uuid.uuid4()),
            dry_run=False,
            targets=self.scope.validate_targets(targets),
            commands=commands,
            assets=assets,
            warnings=warnings,
        )

    @staticmethod
    def _parse_nmap(target: str, output: str) -> list[AssetObservation]:
        ports: list[int] = []
        services: list[str] = []
        for line in output.splitlines():
            match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line.strip())
            if match:
                ports.append(int(match.group(1)))
                services.append(match.group(2))
        return [AssetObservation(ip=target, ports=ports, services=services)] if ports else []
