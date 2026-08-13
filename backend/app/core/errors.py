from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse

_SAFE_ERROR_HEADERS = frozenset({"www-authenticate", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining"})


def request_id(request: Request) -> str:
    existing = getattr(request.state, "request_id", None)
    if isinstance(existing, str) and existing:
        return existing
    generated = str(uuid4())
    request.state.request_id = generated
    return generated


def route_template(request: Request) -> str:
    route = request.scope.get("route")
    value = getattr(route, "path", None)
    return value if isinstance(value, str) else "__unmatched__"


def audit_safe_error(
    audit: Any,
    request: Request,
    *,
    status_code: int,
    error_code: str,
    actor: str = "anonymous",
) -> None:
    audit.record(
        "api.authorization_failure" if status_code in {401, 403} else "api.error",
        {
            "request_id": request_id(request),
            "method": request.method,
            "route": route_template(request),
            "status_code": status_code,
            "error_code": error_code,
        },
        actor=actor,
    )


def safe_error_response(
    request: Request,
    *,
    status_code: int,
    error_code: str,
    message: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    filtered_headers = {
        key: value for key, value in (headers or {}).items() if key.lower() in _SAFE_ERROR_HEADERS
    }
    response = JSONResponse(
        status_code=status_code,
        content={
            "detail": message,
            "error_code": error_code,
            "request_id": request_id(request),
        },
        headers=filtered_headers,
    )
    response.headers["X-Request-ID"] = request_id(request)
    return response
