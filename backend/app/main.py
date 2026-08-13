from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.routes import build_router
from app.core.audit import AuditLogger
from app.core.config import Settings, get_settings
from app.core.errors import audit_safe_error, safe_error_response
from app.core.observability import MetricsRegistry, RequestObservabilityMiddleware, configure_logging
from app.core.ownership import OwnershipDenied


def _actor(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    username = getattr(principal, "username", None)
    return username if isinstance(username, str) else "anonymous"


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    metrics = MetricsRegistry()
    audit = AuditLogger(resolved.audit_log_path)
    configure_logging(resolved.log_level)
    application = FastAPI(
        title="RedPath API",
        version="0.1.0",
        description="Safe-by-design internal AD-lab attack-path simulator and purple-team analyzer.",
    )
    application.state.audit_logger = audit
    application.add_middleware(RequestObservabilityMiddleware, metrics=metrics)
    application.include_router(build_router(resolved, metrics, audit=audit))

    @application.exception_handler(OwnershipDenied)
    async def ownership_denied_handler(request: Request, _: OwnershipDenied) -> JSONResponse:
        audit_safe_error(audit, request, status_code=403, error_code="authorization_denied", actor=_actor(request))
        return safe_error_response(
            request,
            status_code=403,
            error_code="authorization_denied",
            message="Insufficient authorization",
        )

    @application.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        safe_messages = {
            401: ("authentication_required", "Authentication required"),
            403: ("authorization_denied", "Insufficient authorization"),
            404: ("resource_not_found", "Resource not found"),
            429: ("rate_limited", "Rate limit exceeded"),
        }
        error_code, safe_message = safe_messages.get(
            exc.status_code,
            (f"http_{exc.status_code}", str(exc.detail) if isinstance(exc.detail, str) else "Request failed"),
        )
        audit_safe_error(
            audit,
            request,
            status_code=exc.status_code,
            error_code=error_code,
            actor=_actor(request),
        )
        return safe_error_response(
            request,
            status_code=exc.status_code,
            error_code=error_code,
            message=safe_message,
            headers=exc.headers,
        )

    @application.exception_handler(Exception)
    async def internal_error_handler(request: Request, _: Exception) -> JSONResponse:
        audit_safe_error(audit, request, status_code=500, error_code="internal_error", actor=_actor(request))
        return safe_error_response(
            request,
            status_code=500,
            error_code="internal_error",
            message="Internal server error",
        )

    @application.get("/")
    def root() -> dict[str, str]:
        return {"name": "RedPath", "docs": "/docs", "health": "/api/v1/health"}

    return application


app = create_app()
