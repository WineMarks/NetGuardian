from __future__ import annotations

from sqlmodel import Session, select

from app.models.user import User


class UserRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, user: User) -> User:
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        return user

    def get_by_username(self, username: str) -> User | None:
        stmt = select(User).where(User.username == username)
        return self.session.exec(stmt).first()

    def get_by_id(self, user_id: int) -> User | None:
        return self.session.get(User, user_id)

    def list_all(self) -> list[User]:
        stmt = select(User).order_by(User.created_at.desc())
        return list(self.session.exec(stmt).all())

    def list_active_with_notification_channels(self) -> list[User]:
        stmt = (
            select(User)
            .where(User.is_active.is_(True))
            .where(
                (User.webhook_enabled.is_(True) & User.webhook_url.is_not(None))
                | (User.notify_email_verified.is_(True) & User.notify_email.is_not(None))
            )
            .order_by(User.created_at.asc())
        )
        return list(self.session.exec(stmt).all())

    def update(self, user: User) -> User:
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        return user
