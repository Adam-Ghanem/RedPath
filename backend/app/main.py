from fastapi import FastAPI

from app.api.routes import build_router
from app.core.config import get_settings

settings = get_settings()
app = FastAPI(
    title="RedPath API",
    version="0.1.0",
    description="Safe-by-design internal AD-lab attack-path simulator and purple-team analyzer.",
)
app.include_router(build_router(settings))


@app.get("/")
def root() -> dict[str, str]:
    return {"name": "RedPath", "docs": "/docs", "health": "/api/v1/health"}
