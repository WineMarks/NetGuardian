from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from app.api.deps import require_admin
from app.api.schemas import AdminUserUpdateRequest, ErrorResponse, UserProfileResponse
from app.models.user import User
from app.models.user_repository import UserRepository
from app.core.database import get_session
from sqlmodel import Session

router = APIRouter(prefix="/users", tags=["users"])

ERROR_RESPONSES = {
    400: {"description": "Invalid request", "model": ErrorResponse},
    403: {"description": "Forbidden", "model": ErrorResponse},
    404: {"description": "Resource not found", "model": ErrorResponse},
}


def to_user_profile(user: User) -> UserProfileResponse:
    return UserProfileResponse(
        id=int(user.id),
        username=user.username,
        role=user.role,
        is_active=user.is_active,
    )


@router.get(
    "",
    response_model=list[UserProfileResponse],
    responses=ERROR_RESPONSES,
    summary="List all users (admin only)",
)
def list_users(
    _: User = Depends(require_admin),
    session: Session = Depends(get_session),
) -> list[UserProfileResponse]:
    repository = UserRepository(session)
    users = repository.list_all()
    return [to_user_profile(user) for user in users]


@router.patch(
    "/{user_id}",
    response_model=UserProfileResponse,
    responses=ERROR_RESPONSES,
    summary="Update user role or status (admin only)",
)
def update_user(
    user_id: int,
    payload: AdminUserUpdateRequest = Body(...),
    current_admin: User = Depends(require_admin),
    session: Session = Depends(get_session),
) -> UserProfileResponse:
    repository = UserRepository(session)
    user = repository.get_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "User not found"})

    if payload.role is None and payload.is_active is None:
        raise HTTPException(status_code=400, detail={"code": "INVALID_INPUT", "message": "No update fields provided"})

    if int(current_admin.id) == int(user.id):
        if payload.role == "user":
            raise HTTPException(status_code=400, detail={"code": "INVALID_INPUT", "message": "You cannot demote yourself"})
        if payload.is_active is False:
            raise HTTPException(status_code=400, detail={"code": "INVALID_INPUT", "message": "You cannot deactivate yourself"})

    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active

    user = repository.update(user)
    return to_user_profile(user)
