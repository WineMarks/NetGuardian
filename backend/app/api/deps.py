from __future__ import annotations

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlmodel import Session

from app.core.config import Settings, get_settings
from app.core.database import get_session
from app.models.ip_list_repository import IpListRepository
from app.models.user import User
from app.models.repository import TrafficLogRepository
from app.models.user_repository import UserRepository
from app.services.auth_service import AuthService
from app.services.ip_list_service import IpListService
from app.services.notification_service import NotificationService
from app.services.security import decode_access_token
from app.services.traffic_service import TrafficService

bearer_scheme = HTTPBearer(auto_error=False)


def get_traffic_service(
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> TrafficService:
    repository = TrafficLogRepository(session)
    ip_list_repository = IpListRepository(session)
    ip_list_service = IpListService(repository=ip_list_repository)
    notify_service = NotificationService(repository=UserRepository(session), settings=settings)
    return TrafficService(
        repository=repository,
        settings=settings,
        ip_list_service=ip_list_service,
        notification_service=notify_service,
    )


def get_auth_service(
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> AuthService:
    repository = UserRepository(session)
    return AuthService(repository=repository, settings=settings)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    auth_service: AuthService = Depends(get_auth_service),
    settings: Settings = Depends(get_settings),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=401, detail={"code": "UNAUTHORIZED", "message": "Missing bearer token"})

    try:
        payload = decode_access_token(credentials.credentials, settings)
        user_id = int(payload.get("sub", 0))
        user = auth_service.get_user(user_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail={"code": "UNAUTHORIZED", "message": "Invalid access token"}) from exc

    if not user.is_active:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "Inactive user"})

    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "Admin role required"})
    return current_user
