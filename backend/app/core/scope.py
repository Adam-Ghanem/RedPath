from __future__ import annotations

import ipaddress
from dataclasses import dataclass


class ScopeViolation(ValueError):
    """Raised when a target falls outside the configured lab scope."""


@dataclass(frozen=True)
class ScopePolicy:
    allowed_cidrs: tuple[str, ...]

    @classmethod
    def from_strings(cls, cidrs: list[str]) -> "ScopePolicy":
        normalized = tuple(str(ipaddress.ip_network(cidr, strict=False)) for cidr in cidrs)
        if not normalized:
            raise ValueError("At least one allowed CIDR is required")
        return cls(normalized)

    @property
    def networks(self) -> tuple[ipaddress._BaseNetwork, ...]:
        return tuple(ipaddress.ip_network(cidr) for cidr in self.allowed_cidrs)

    def validate_ip(self, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ScopeViolation(f"Invalid IP address: {value}") from exc
        if not any(address in network for network in self.networks):
            raise ScopeViolation(f"Target {value} is outside the configured lab scope")
        return str(address)

    def validate_targets(self, targets: list[str]) -> list[str]:
        if not targets:
            raise ScopeViolation("At least one target is required")
        return [self.validate_ip(target) for target in targets]
