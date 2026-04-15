from __future__ import annotations

from datetime import datetime

from sqlmodel import Field, SQLModel


class IpListEntry(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow, index=True)

    ip: str = Field(index=True, unique=True, min_length=3, max_length=64)
    list_type: str = Field(index=True)  # blacklist | graylist
    enabled: bool = Field(default=True, index=True)
    reason: str | None = None
    expires_at: datetime | None = Field(default=None, index=True)
    created_by: str | None = Field(default=None, max_length=64)
