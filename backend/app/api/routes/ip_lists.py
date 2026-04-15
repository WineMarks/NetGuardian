from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlmodel import Session

from app.api.deps import get_current_user, require_admin
from app.api.schemas import ErrorResponse, IpListEntryResponse, IpListUpdateRequest, IpListUpsertRequest
from app.core.database import get_session
from app.core.exceptions import AppError
from app.models.ip_list_entry import IpListEntry
from app.models.ip_list_repository import IpListRepository
from app.models.user import User
from app.services.ip_list_service import IpListService

router = APIRouter(prefix="/ip-lists", tags=["ip-lists"])

ERROR_RESPONSES = {
    400: {"description": "Invalid request", "model": ErrorResponse},
    403: {"description": "Forbidden", "model": ErrorResponse},
    404: {"description": "Resource not found", "model": ErrorResponse},
}


def to_response(entry: IpListEntry) -> IpListEntryResponse:
    return IpListEntryResponse(
        id=int(entry.id),
        created_at=entry.created_at,
        updated_at=entry.updated_at,
        ip=entry.ip,
        list_type=entry.list_type,
        reason=entry.reason,
        expires_at=entry.expires_at,
        created_by=entry.created_by,
    )


def get_service(session: Session = Depends(get_session)) -> IpListService:
    return IpListService(repository=IpListRepository(session))


@router.get(
    "",
    response_model=list[IpListEntryResponse],
    responses=ERROR_RESPONSES,
    summary="List IP graylist/blacklist entries",
)
def list_entries(
    list_type: str | None = Query(default=None),
    active_only: bool = Query(default=False),
    limit: int = Query(default=500, ge=1, le=2000),
    _: User = Depends(get_current_user),
    service: IpListService = Depends(get_service),
) -> list[IpListEntryResponse]:
    try:
        rows = service.list_entries(list_type=list_type, active_only=active_only, limit=limit)
        return [to_response(row) for row in rows]
    except AppError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc


@router.post(
    "",
    response_model=IpListEntryResponse,
    responses=ERROR_RESPONSES,
    summary="Add or update IP list entry",
)
def upsert_entry(
    payload: IpListUpsertRequest = Body(...),
    user: User = Depends(get_current_user),
    service: IpListService = Depends(get_service),
) -> IpListEntryResponse:
    try:
        row = service.upsert(
            ip=payload.ip,
            list_type=payload.list_type,
            reason=payload.reason,
            gray_duration_minutes=payload.gray_duration_minutes,
            expires_at=payload.expires_at,
            created_by=user.username,
        )
        return to_response(row)
    except AppError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc


@router.patch(
    "/{entry_id}",
    response_model=IpListEntryResponse,
    responses=ERROR_RESPONSES,
    summary="Modify IP list entry",
)
def update_entry(
    entry_id: int,
    payload: IpListUpdateRequest = Body(...),
    user: User = Depends(get_current_user),
    service: IpListService = Depends(get_service),
) -> IpListEntryResponse:
    existing = service.repository.get_by_id(entry_id)
    if existing is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "IP list entry not found"})

    list_type = payload.list_type or existing.list_type
    reason = payload.reason if payload.reason is not None else existing.reason

    try:
        row = service.upsert(
            ip=existing.ip,
            list_type=list_type,
            reason=reason,
            gray_duration_minutes=payload.gray_duration_minutes,
            expires_at=payload.expires_at,
            created_by=user.username,
        )
        return to_response(row)
    except AppError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc


@router.delete(
    "/{entry_id}",
    responses=ERROR_RESPONSES,
    summary="Delete IP list entry",
)
def delete_entry(
    entry_id: int,
    _: User = Depends(get_current_user),
    service: IpListService = Depends(get_service),
) -> dict[str, bool]:
    try:
        service.remove(entry_id)
    except AppError as exc:
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.message}) from exc
    return {"ok": True}
