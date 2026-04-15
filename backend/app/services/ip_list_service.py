from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.core.exceptions import InvalidInputError, NotFoundError
from app.models.ip_list_entry import IpListEntry
from app.models.ip_list_repository import IpListRepository


@dataclass(slots=True)
class IpHitResult:
    hit: bool
    list_type: str | None = None
    reason: str | None = None
    expires_at: datetime | None = None


class IpListService:
    def __init__(self, repository: IpListRepository) -> None:
        self.repository = repository

    def check_hit(self, ip: str | None) -> IpHitResult:
        if not ip:
            return IpHitResult(hit=False)

        entry = self.repository.get_by_ip(ip)
        if entry is None:
            return IpHitResult(hit=False)

        if not entry.enabled:
            return IpHitResult(hit=False)

        now = datetime.utcnow()
        if entry.list_type == "blacklist":
            return IpHitResult(hit=True, list_type="blacklist", reason=entry.reason, expires_at=None)

        if entry.list_type == "graylist":
            if entry.expires_at and entry.expires_at > now:
                return IpHitResult(hit=True, list_type="graylist", reason=entry.reason, expires_at=entry.expires_at)
            return IpHitResult(hit=False)

        return IpHitResult(hit=False)

    def list_entries(self, *, list_type: str | None, active_only: bool, limit: int = 500) -> list[IpListEntry]:
        self._validate_list_type_or_none(list_type)
        return self.repository.list_entries(list_type=list_type, active_only=active_only, limit=limit)

    def upsert(
        self,
        *,
        ip: str,
        list_type: str,
        reason: str | None,
        gray_duration_minutes: int | None,
        expires_at: datetime | None,
        created_by: str | None,
    ) -> IpListEntry:
        self._validate_list_type(list_type)

        normalized_ip = (ip or "").strip()
        if not normalized_ip:
            raise InvalidInputError("ip is required")

        final_expires_at = None
        if list_type == "graylist":
            if gray_duration_minutes is None and expires_at is None:
                raise InvalidInputError("graylist requires gray_duration_minutes or expires_at")
            if gray_duration_minutes is not None:
                if gray_duration_minutes <= 0:
                    raise InvalidInputError("gray_duration_minutes must be greater than 0")
                final_expires_at = datetime.utcnow() + timedelta(minutes=gray_duration_minutes)
            else:
                final_expires_at = expires_at
        else:
            final_expires_at = None

        return self.repository.upsert(
            ip=normalized_ip,
            list_type=list_type,
            reason=reason,
            expires_at=final_expires_at,
            created_by=created_by,
        )

    def remove(self, entry_id: int) -> None:
        entry = self.repository.get_by_id(entry_id)
        if entry is None:
            raise NotFoundError("IP list entry not found")
        self.repository.delete(entry)

    def _validate_list_type(self, list_type: str) -> None:
        if list_type not in {"blacklist", "graylist"}:
            raise InvalidInputError("list_type must be one of: blacklist, graylist")

    def _validate_list_type_or_none(self, list_type: str | None) -> None:
        if list_type is None:
            return
        self._validate_list_type(list_type)
