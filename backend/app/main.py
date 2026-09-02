from fastapi import FastAPI

from backend.app.api.routes.health import router as health_router
from backend.app.core.config import settings


app = FastAPI(
    title=settings.app_name,
    debug=settings.debug
)

app.include_router(health_router)