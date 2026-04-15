from __future__ import annotations

from datetime import datetime
from typing import Iterable

from sqlmodel import Session, func, select

from app.models.traffic_log import TrafficLog


class TrafficLogRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, log: TrafficLog) -> TrafficLog:
        self.session.add(log)
        self.session.commit()
        self.session.refresh(log)
        return log

    def get_by_id(self, log_id: int) -> TrafficLog | None:
        return self.session.get(TrafficLog, log_id)

    def list_recent(self, limit: int = 100) -> list[TrafficLog]:
        statement = select(TrafficLog).order_by(TrafficLog.created_at.desc()).limit(limit)
        return list(self.session.exec(statement).all())

    def list_filtered(
        self,
        *,
        limit: int = 100,
        status: str | None = None,
        action: str | None = None,
        label: str | None = None,
    ) -> list[TrafficLog]:
        statement = select(TrafficLog)

        if status:
            statement = statement.where(TrafficLog.status == status)
        if action:
            statement = statement.where(TrafficLog.action == action)
        if label:
            statement = statement.where(TrafficLog.predicted_label == label)

        statement = statement.order_by(TrafficLog.created_at.desc()).limit(limit)
        return list(self.session.exec(statement).all())

    def count_filtered(
        self,
        *,
        status: str | None = None,
        action: str | None = None,
        label: str | None = None,
        exclude_actions: Iterable[str] | None = None,
    ) -> int:
        statement = select(func.count()).select_from(TrafficLog)

        if status:
            statement = statement.where(TrafficLog.status == status)
        if action:
            statement = statement.where(TrafficLog.action == action)
        if label:
            statement = statement.where(TrafficLog.predicted_label == label)
        if exclude_actions:
            statement = statement.where(TrafficLog.action.not_in(list(exclude_actions)))

        return int(self.session.exec(statement).one())

    def save(self, log: TrafficLog) -> TrafficLog:
        self.session.add(log)
        self.session.commit()
        self.session.refresh(log)
        return log

    def list_attack_logs_since(
        self,
        *,
        since: datetime,
        limit: int = 500,
        exclude_actions: Iterable[str] | None = None,
    ) -> list[TrafficLog]:
        statement = (
            select(TrafficLog)
            .where(TrafficLog.created_at >= since)
            .where(TrafficLog.is_attack.is_(True))
        )
        if exclude_actions:
            statement = statement.where(TrafficLog.action.not_in(list(exclude_actions)))

        statement = statement.order_by(TrafficLog.created_at.desc()).limit(limit)
        return list(self.session.exec(statement).all())

    def list_source_logs_since(
        self,
        *,
        since: datetime,
        limit: int = 5000,
        exclude_actions: Iterable[str] | None = None,
    ) -> list[TrafficLog]:
        statement = (
            select(TrafficLog)
            .where(TrafficLog.created_at >= since)
            .where(TrafficLog.source_ip.is_not(None))
        )
        if exclude_actions:
            statement = statement.where(TrafficLog.action.not_in(list(exclude_actions)))

        statement = statement.order_by(TrafficLog.created_at.desc()).limit(limit)
        return list(self.session.exec(statement).all())

    def list_recent_by_source(
        self,
        *,
        source_ip: str,
        limit: int = 20,
        exclude_actions: Iterable[str] | None = None,
    ) -> list[TrafficLog]:
        statement = (
            select(TrafficLog)
            .where(TrafficLog.source_ip == source_ip)
            .order_by(TrafficLog.created_at.desc())
            .limit(limit)
        )
        if exclude_actions:
            statement = statement.where(TrafficLog.action.not_in(list(exclude_actions)))
        return list(self.session.exec(statement).all())

    def list_pending_by_source_label_since(
        self,
        *,
        source_ip: str,
        label: str,
        since: datetime,
    ) -> list[TrafficLog]:
        statement = (
            select(TrafficLog)
            .where(TrafficLog.status == "pending_review")
            .where(TrafficLog.source_ip == source_ip)
            .where(TrafficLog.predicted_label == label)
            .where(TrafficLog.created_at >= since)
            .order_by(TrafficLog.created_at.asc())
        )
        return list(self.session.exec(statement).all())
