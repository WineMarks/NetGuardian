from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.auth import router as auth_router
from app.api.routes.chat import router as chat_router
from app.api.routes.collector import router as collector_router
from app.api.routes.health import router as health_router
from app.api.routes.ip_lists import router as ip_lists_router
from app.api.routes.notifications import router as notifications_router
from app.api.routes.traffic import router as traffic_router
from app.api.routes.users import router as users_router
from app.api.routes.ws import router as ws_router
from app.core.config import get_settings
from app.core.database import init_db

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


app.include_router(health_router, prefix=settings.api_v1_prefix)
app.include_router(auth_router, prefix=settings.api_v1_prefix)
app.include_router(chat_router, prefix=settings.api_v1_prefix)
app.include_router(collector_router, prefix=settings.api_v1_prefix)
app.include_router(traffic_router, prefix=settings.api_v1_prefix)
app.include_router(ip_lists_router, prefix=settings.api_v1_prefix)
app.include_router(notifications_router, prefix=settings.api_v1_prefix)
app.include_router(users_router, prefix=settings.api_v1_prefix)
app.include_router(ws_router, prefix=settings.api_v1_prefix)
