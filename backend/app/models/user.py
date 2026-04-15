from __future__ import annotations

from datetime import datetime

from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)

    username: str = Field(index=True, unique=True, min_length=3, max_length=64)
    password_hash: str
    role: str = Field(default="user", index=True)
    is_active: bool = Field(default=True, index=True)

    webhook_url: str | None = Field(default=None, max_length=1024)
    webhook_enabled: bool = Field(default=False, index=True)

    notify_email: str | None = Field(default=None, max_length=256)
    notify_email_verified: bool = Field(default=False, index=True)
    notify_email_pending: str | None = Field(default=None, max_length=256)
    notify_email_code: str | None = Field(default=None, max_length=16)
    notify_email_code_expires_at: datetime | None = Field(default=None, index=True)

    chat_api_key: str | None = Field(default=None, max_length=256)
