from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlmodel import Session

from app.api.deps import get_current_user
from app.api.schemas import (
    EmailCodeSendRequest,
    EmailCodeVerifyRequest,
    ErrorResponse,
    NotificationBindingResponse,
    WebhookBindRequest,
)
from app.core.config import Settings, get_settings
from app.core.database import get_session
from app.core.exceptions import AppError
from app.models.user import User
from app.models.user_repository import UserRepository
from app.services.notification_service import NotificationService

router = APIRouter(prefix="/notifications", tags=["notifications"])

ERROR_RESPONSES = {
    400: {"description": "Invalid request", "model": ErrorResponse},
    401: {"description": "Unauthorized", "model": ErrorResponse},
}


def get_service(
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> NotificationService:
    return NotificationService(repository=UserRepository(session), settings=settings)


def to_response(current_user: User, service: NotificationService) -> NotificationBindingResponse:
    info = service.get_binding_info(current_user)
    return NotificationBindingResponse(
        webhook_url=info.webhook_url,
        webhook_enabled=info.webhook_enabled,
        notify_email=info.notify_email,
        notify_email_verified=info.notify_email_verified,
        pending_email=info.pending_email,
        urgent_threshold=info.urgent_threshold,
    )


@router.get("/me", response_model=NotificationBindingResponse, responses=ERROR_RESPONSES, summary="Get my notification binding")
def get_my_notifications(
    current_user: User = Depends(get_current_user),
    service: NotificationService = Depends(get_service),
) -> NotificationBindingResponse:
    return to_response(current_user, service)


@router.put("/webhook", response_model=NotificationBindingResponse, responses=ERROR_RESPONSES, summary="Bind webhook")
def bind_webhook(
    payload: WebhookBindRequest = Body(...),
    current_user: User = Depends(get_current_user),
    service: NotificationService = Depends(get_service),
) -> NotificationBindingResponse:
    try:
        updated = service.bind_webhook(user=current_user, webhook_url=payload.webhook_url, enabled=payload.enabled)
        return to_response(updated, service)
    except AppError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc


@router.post(
    "/email/send-code",
    responses=ERROR_RESPONSES,
    summary="Send email verification code",
)
def send_email_code(
    payload: EmailCodeSendRequest = Body(...),
    current_user: User = Depends(get_current_user),
    service: NotificationService = Depends(get_service),
) -> dict[str, bool]:
    try:
        service.send_email_verification_code(user=current_user, email=payload.email)
        return {"ok": True}
    except AppError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc


@router.post(
    "/email/verify",
    response_model=NotificationBindingResponse,
    responses=ERROR_RESPONSES,
    summary="Verify email binding code",
)
def verify_email_code(
    payload: EmailCodeVerifyRequest = Body(...),
    current_user: User = Depends(get_current_user),
    service: NotificationService = Depends(get_service),
) -> NotificationBindingResponse:
    try:
        updated = service.verify_email_code(user=current_user, email=payload.email, code=payload.code)
        return to_response(updated, service)
    except AppError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc


@router.delete(
    "/email",
    response_model=NotificationBindingResponse,
    responses=ERROR_RESPONSES,
    summary="Remove email binding",
)
def clear_email_binding(
    current_user: User = Depends(get_current_user),
    service: NotificationService = Depends(get_service),
) -> NotificationBindingResponse:
    updated = service.clear_email_binding(user=current_user)
    return to_response(updated, service)
