"""Report SLO status and error-budget posture from aggregate counters only."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

MAX_SAMPLES = 10_000
MAX_WINDOW_MINUTES = 43_200
TARGET_AVAILABILITY = 0.995
TARGET_ERROR_RATE = 0.01
TARGET_P95_LATENCY_MS = 1_000.0


def p95(samples: list[float]) -> float:
    ordered = sorted(samples)
    index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return ordered[index]


def report(data: dict[str, object]) -> dict[str, object]:
    window = int(data["window_minutes"])
    requests = int(data["requests_total"])
    server_errors = int(data["server_errors"])
    ready_checks = int(data["ready_checks_total"])
    ready_failures = int(data["ready_failures"])
    latencies = [float(value) for value in data["latency_ms"]]  # type: ignore[index]
    audit_failures = int(data["audit_failures"])
    tenant_failures = int(data["tenant_boundary_failures"])

    if window < 1 or window > MAX_WINDOW_MINUTES:
        raise ValueError("window_minutes is outside the supported bound")
    if requests < 1 or server_errors < 0 or server_errors > requests:
        raise ValueError("request counters are invalid")
    if ready_checks < 1 or ready_failures < 0 or ready_failures > ready_checks:
        raise ValueError("readiness counters are invalid")
    if not latencies or len(latencies) > MAX_SAMPLES or any(value < 0 or value > 300_000 for value in latencies):
        raise ValueError("latency samples are outside the supported bound")
    if audit_failures < 0 or tenant_failures < 0:
        raise ValueError("integrity counters are invalid")

    availability = (ready_checks - ready_failures) / ready_checks
    error_rate = server_errors / requests
    latency_p95 = p95(latencies)
    availability_budget = max(0.0, (1.0 - TARGET_AVAILABILITY) * ready_checks - ready_failures)
    error_budget = max(0.0, TARGET_ERROR_RATE * requests - server_errors)
    availability_budget_fraction = availability_budget / max(1.0, (1.0 - TARGET_AVAILABILITY) * ready_checks)
    error_budget_fraction = error_budget / max(1.0, TARGET_ERROR_RATE * requests)
    checks_pass = (
        availability >= TARGET_AVAILABILITY
        and error_rate <= TARGET_ERROR_RATE
        and latency_p95 <= TARGET_P95_LATENCY_MS
        and audit_failures == 0
        and tenant_failures == 0
    )
    return {
        "status": "pass" if checks_pass else "pause_promotion",
        "window_minutes": window,
        "availability": round(availability, 6),
        "error_rate": round(error_rate, 6),
        "p95_latency_ms": latency_p95,
        "error_budget_remaining_fraction": round(min(availability_budget_fraction, error_budget_fraction), 6),
        "audit_failures": audit_failures,
        "tenant_boundary_failures": tenant_failures,
        "safe_failure": "pause promotion and preserve aggregate diagnostics" if not checks_pass else "none",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = report(json.loads(args.input.read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"SLO report failed safely: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            "SLO report: status={status}, availability={availability}, error_rate={error_rate}, "
            "p95_latency_ms={p95_latency_ms}, error_budget_remaining_fraction={error_budget_remaining_fraction}".format(
                **result
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
