from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from app.api.deps import get_auth_service, get_current_user
from app.api.schemas import (
    AuthTokenResponse,
    ErrorResponse,
    LoginRequest,
    RegisterRequest,
    UserProfileResponse,
)
from app.core.exceptions import AppError
from app.models.user import User
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])

ERROR_RESPONSES = {
    400: {
        "description": "Invalid request",
        "model": ErrorResponse,
    },
    401: {
        "description": "Unauthorized",
        "model": ErrorResponse,
    },
    403: {
        "description": "Forbidden",
        "model": ErrorResponse,
    },
    404: {
        "description": "Resource not found",
        "model": ErrorResponse,
    },
}


def to_error_detail(*, code: str, message: str, detail: str | None = None) -> dict[str, str | None]:
    return ErrorResponse(code=code, message=message, detail=detail).model_dump()


def to_user_profile(user: User) -> UserProfileResponse:
    return UserProfileResponse(id=int(user.id), username=user.username, role=user.role, is_active=user.is_active)


@router.post(
    "/register",
    response_model=UserProfileResponse,
    responses=ERROR_RESPONSES,
    summary="Register a new user",
)
def register(
    payload: RegisterRequest = Body(
        ...,
        examples=[
            {
                "summary": "Regular user",
                "value": {
                    "username": "analyst01",
                    "password": "strongpass123",
                    "role": "user",
                },
            },
            {
                "summary": "Admin user",
                "value": {
                    "username": "secadmin",
                    "password": "strongpass123",
                    "role": "admin",
                    "admin_code": "YOUR_ADMIN_CODE",
                },
            },
        ],
    ),
    auth_service: AuthService = Depends(get_auth_service),
) -> UserProfileResponse:
    try:
        user = auth_service.register(
            username=payload.username,
            password=payload.password,
            role=payload.role,
            admin_code=payload.admin_code,
        )
        return to_user_profile(user)
    except AppError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=to_error_detail(code=exc.code, message=exc.message),
        ) from exc


@router.post(
    "/login",
    response_model=AuthTokenResponse,
    responses=ERROR_RESPONSES,
    summary="Authenticate and receive access token",
)
def login(
    payload: LoginRequest = Body(
        ...,
        examples=[
            {
                "summary": "User login",
                "value": {
                    "username": "analyst01",
                    "password": "strongpass123",
                },
            }
        ],
    ),
    auth_service: AuthService = Depends(get_auth_service),
) -> AuthTokenResponse:
    try:
        result = auth_service.login(username=payload.username, password=payload.password)
        user = auth_service.get_user(result.user_id)
    except AppError as exc:
        status_code = 401 if exc.code in {"NOT_FOUND", "INVALID_INPUT"} else exc.status_code
        code = "UNAUTHORIZED" if status_code == 401 else exc.code
        raise HTTPException(
            status_code=status_code,
            detail=to_error_detail(code=code, message=exc.message),
        ) from exc

    return AuthTokenResponse(
        access_token=result.access_token,
        token_type=result.token_type,
        user=to_user_profile(user),
    )


@router.get(
    "/me",
    response_model=UserProfileResponse,
    responses=ERROR_RESPONSES,
    summary="Get current user profile",
)
def me(current_user: User = Depends(get_current_user)) -> UserProfileResponse:
    return to_user_profile(current_user)
