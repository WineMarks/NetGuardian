from __future__ import annotations

from datetime import datetime

from sqlmodel import Session, select

from app.models.ip_list_entry import IpListEntry


class IpListRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_by_id(self, entry_id: int) -> IpListEntry | None:
        return self.session.get(IpListEntry, entry_id)

    def get_by_ip(self, ip: str) -> IpListEntry | None:
        statement = select(IpListEntry).where(IpListEntry.ip == ip)
        return self.session.exec(statement).first()

    def list_entries(
        self,
        *,
        list_type: str | None = None,
        active_only: bool = False,
        now: datetime | None = None,
        limit: int = 500,
    ) -> list[IpListEntry]:
        statement = select(IpListEntry)
        if list_type:
            statement = statement.where(IpListEntry.list_type == list_type)
        statement = statement.where(IpListEntry.enabled.is_(True))

        rows = list(self.session.exec(statement.order_by(IpListEntry.updated_at.desc()).limit(limit)).all())
        if not active_only:
            return rows

        ts = now or datetime.utcnow()
        result: list[IpListEntry] = []
        for row in rows:
            if row.list_type == "blacklist":
                result.append(row)
                continue
            if row.list_type == "graylist" and row.expires_at and row.expires_at > ts:
                result.append(row)
        return result

    def upsert(
        self,
        *,
        ip: str,
        list_type: str,
        reason: str | None,
        expires_at: datetime | None,
        created_by: str | None,
    ) -> IpListEntry:
        now = datetime.utcnow()
        entry = self.get_by_ip(ip)
        if entry is None:
            entry = IpListEntry(
                ip=ip,
                list_type=list_type,
                reason=reason,
                expires_at=expires_at,
                created_by=created_by,
                created_at=now,
                updated_at=now,
            )
        else:
            entry.list_type = list_type
            entry.reason = reason
            entry.expires_at = expires_at
            if created_by:
                entry.created_by = created_by
            entry.updated_at = now

        self.session.add(entry)
        self.session.commit()
        self.session.refresh(entry)
        return entry

    def save(self, entry: IpListEntry) -> IpListEntry:
        entry.updated_at = datetime.utcnow()
        self.session.add(entry)
        self.session.commit()
        self.session.refresh(entry)
        return entry

    def delete(self, entry: IpListEntry) -> None:
        self.session.delete(entry)
        self.session.commit()
