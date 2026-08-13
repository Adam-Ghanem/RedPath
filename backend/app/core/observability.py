from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from threading import Lock
from time import perf_counter
from typing import Any
from uuid import UUID, uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_TELEMETRY_COUNTER_NAMES = frozenset(
    {
        "ingest_attempts_total",
        "ingest_success_total",
        "ingest_failures_total",
        "dead_letters_total",
        "schema_drift_total",
        "correlation_evaluations_total",
        "correlation_matches_total",
        "checkpoint_recoveries_total",
        "retention_pruned_total",
    }
)
_TELEMETRY_GAUGE_NAMES = frozenset({"lag_seconds", "consecutive_failures", "dead_letter_count"})
def _safe_request_id(value: str | None) -> str:
    if value and _REQUEST_ID_PATTERN.fullmatch(value):
        return value
    return str(uuid4())


def _route_label(request: Request) -> str:
    route = request.scope.get("route")
    route_path = getattr(route, "path", None)
    if isinstance(route_path, str):
        return route_path
    return "__unmatched__"


def _label_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class MetricsRegistry:
    """Small in-process metrics registry suitable for a single API worker.

    Labels are limited to HTTP method, route template, and status class to avoid
    exposing query parameters or creating unbounded cardinality.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._requests: defaultdict[tuple[str, str, str], int] = defaultdict(int)
        self._duration_seconds: defaultdict[tuple[str, str], float] = defaultdict(float)
        self._duration_count: defaultdict[tuple[str, str], int] = defaultdict(int)
        self._telemetry_counters: defaultdict[str, int] = defaultdict(int)
        self._telemetry_gauges: dict[str, float] = {}
        self._in_flight = 0

    def start_request(self) -> None:
        with self._lock:
            self._in_flight += 1

    def finish_request(self, method: str, route: str, status_code: int, duration_seconds: float) -> None:
        status_class = f"{status_code // 100}xx"
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)
            self._requests[(method, route, status_class)] += 1
            self._duration_seconds[(method, route)] += duration_seconds
            self._duration_count[(method, route)] += 1

    def increment_telemetry(self, name: str, amount: int = 1) -> None:
        if name not in _TELEMETRY_COUNTER_NAMES or amount < 0:
            raise ValueError("unsupported telemetry counter")
        with self._lock:
            self._telemetry_counters[name] += amount

    def set_telemetry_gauge(self, name: str, value: float) -> None:
        if name not in _TELEMETRY_GAUGE_NAMES or value < 0:
            raise ValueError("unsupported telemetry gauge")
        with self._lock:
            self._telemetry_gauges[name] = float(value)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "in_flight": self._in_flight,
                "requests": dict(self._requests),
                "durations": dict(self._duration_seconds),
                "duration_counts": dict(self._duration_count),
                "telemetry_counters": dict(self._telemetry_counters),
                "telemetry_gauges": dict(self._telemetry_gauges),
            }

    def prometheus(self) -> str:
        snapshot = self.snapshot()
        lines = [
            "# HELP redpath_http_requests_total Total HTTP requests handled by the API.",
            "# TYPE redpath_http_requests_total counter",
        ]
        for (method, route, status_class), count in sorted(snapshot["requests"].items()):
            labels = (
                f'method="{_label_escape(method)}",'
                f'route="{_label_escape(route)}",'
                f'status_class="{_label_escape(status_class)}"'
            )
            lines.append(f"redpath_http_requests_total{{{labels}}} {count}")

        lines.extend(
            [
                "# HELP redpath_http_request_duration_seconds_sum Cumulative HTTP request duration in seconds.",
                "# TYPE redpath_http_request_duration_seconds_sum counter",
            ]
        )
        for (method, route), duration in sorted(snapshot["durations"].items()):
            labels = f'method="{_label_escape(method)}",route="{_label_escape(route)}"'
            lines.append(f"redpath_http_request_duration_seconds_sum{{{labels}}} {duration:.6f}")

        lines.extend(
            [
                "# HELP redpath_http_request_duration_seconds_count Number of HTTP requests measured.",
                "# TYPE redpath_http_request_duration_seconds_count counter",
            ]
        )
        for (method, route), count in sorted(snapshot["duration_counts"].items()):
            labels = f'method="{_label_escape(method)}",route="{_label_escape(route)}"'
            lines.append(f"redpath_http_request_duration_seconds_count{{{labels}}} {count}")

        lines.extend(
            [
                "# HELP redpath_telemetry_events_total Bounded telemetry resilience counters.",
                "# TYPE redpath_telemetry_events_total counter",
            ]
        )
        for name, count in sorted(snapshot["telemetry_counters"].items()):
            lines.append(f"redpath_telemetry_{name} {count}")
        lines.extend(
            [
                "# HELP redpath_telemetry_state Bounded telemetry resilience gauges.",
                "# TYPE redpath_telemetry_state gauge",
            ]
        )
        for name, value in sorted(snapshot["telemetry_gauges"].items()):
            lines.append(f"redpath_telemetry_{name} {value:.3f}")

        lines.extend(
            [
                "# HELP redpath_http_requests_in_flight Current number of HTTP requests being handled.",
                "# TYPE redpath_http_requests_in_flight gauge",
                f"redpath_http_requests_in_flight {snapshot['in_flight']}",
                "",
            ]
        )
        return "\n".join(lines)


class RedactingJsonFormatter(logging.Formatter):
    """Emit stable JSON logs without request bodies, headers, or secret fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("request_id", "method", "route", "status_code", "duration_ms"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, sort_keys=True)


def configure_logging(level: str = "INFO") -> None:
    logger = logging.getLogger("redpath.http")
    if logger.handlers:
        logger.setLevel(level.upper())
        return
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingJsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level.upper())
    logger.propagate = False


class RequestObservabilityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, metrics: MetricsRegistry) -> None:
        super().__init__(app)
        self.metrics = metrics
        self.logger = logging.getLogger("redpath.http")

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        request_id = _safe_request_id(request.headers.get("X-Request-ID"))
        request.state.request_id = request_id
        started = perf_counter()
        self.metrics.start_request()
        response: Response | None = None
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            self.logger.exception(
                "http.request.failed",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "route": _route_label(request),
                    "status_code": status_code,
                    "duration_ms": round((perf_counter() - started) * 1000, 2),
                },
            )
            raise
        finally:
            duration_seconds = perf_counter() - started
            route = _route_label(request)
            self.metrics.finish_request(request.method, route, status_code, duration_seconds)
            if response is not None:
                response.headers["X-Request-ID"] = request_id
                response.headers["Server-Timing"] = f"app;dur={duration_seconds * 1000:.2f}"
                self.logger.info(
                    "http.request.completed",
                    extra={
                        "request_id": request_id,
                        "method": request.method,
                        "route": route,
                        "status_code": status_code,
                        "duration_ms": round(duration_seconds * 1000, 2),
                    },
                )


def is_uuid(value: str) -> bool:
    """Expose a small testable helper for correlation-id validation."""

    try:
        UUID(value)
    except ValueError:
        return False
    return True
