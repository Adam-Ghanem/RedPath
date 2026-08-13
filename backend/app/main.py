from __future__ import annotations

from fastapi import FastAPI

from app.api.routes import build_router
from app.core.config import Settings, get_settings


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    application = FastAPI(
        title="RedPath API",
        version="0.1.0",
        description="Safe-by-design internal AD-lab attack-path simulator and purple-team analyzer.",
    )
    application.include_router(build_router(resolved))

    @application.get("/")
    def root() -> dict[str, str]:
        return {"name": "RedPath", "docs": "/docs", "health": "/api/v1/health"}

    return application


app = create_app()
