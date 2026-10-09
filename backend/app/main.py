from fastapi import FastAPI

from backend.app.api.routes.health import router as health_router
from backend.app.api.routes.db_test import router as db_test_router
from backend.app.core.config import settings
from backend.app.core.init_db import init_db
from backend.app.api.routes.auth import router as auth_router

app = FastAPI(
    title=settings.app_name,
    debug=settings.debug
)


@app.on_event("startup")
def startup():
    init_db()


app.include_router(health_router)
app.include_router(db_test_router)
app.include_router(auth_router)