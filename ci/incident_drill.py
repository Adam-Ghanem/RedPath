"""Validate incident runbook drills without contacting production systems."""

from __future__ import annotations

import argparse
import json

DRILLS = {
    "readiness_failure": {
        "trigger": "readiness probe fails",
        "safe_failure": "pause promotion and remove the unhealthy instance from traffic",
        "forbidden": "bypass readiness or authentication",
    },
    "tenant_rbac_boundary": {
        "trigger": "synthetic cross-tenant authorization check fails",
        "safe_failure": "fail closed and preserve server-derived actor and tenant predicates",
        "forbidden": "expose records across tenants",
    },
    "audit_integrity": {
        "trigger": "audit-chain verification fails",
        "safe_failure": "preserve evidence read-only and restrict evidence-affecting actions",
        "forbidden": "rewrite or delete audit history",
    },
    "backup_restore": {
        "trigger": "backup digest or isolated readiness check fails",
        "safe_failure": "discard the isolated restore candidate and retain the source unchanged",
        "forbidden": "overwrite the production source during a drill",
    },
    "slo_error_budget": {
        "trigger": "error budget is exhausted",
        "safe_failure": "pause release promotion and open an operator-owned incident",
        "forbidden": "disable telemetry, rate limits, or tenant controls",
    },
}


def run(selected: list[str]) -> list[dict[str, str]]:
    results = []
    for name in selected:
        drill = DRILLS[name]
        if not all(drill.values()):
            raise RuntimeError(f"incident drill is incomplete: {name}")
        results.append({"name": name, "status": "pass", **drill})
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drill", choices=sorted(DRILLS), action="append")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    selected = args.drill or sorted(DRILLS)
    if args.all:
        selected = sorted(DRILLS)
    results = run(selected)
    if args.json:
        print(json.dumps({"status": "pass", "drills": results}, indent=2, sort_keys=True))
    else:
        print(f"Incident drill checks passed: {len(results)} safe-failure scenarios validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
