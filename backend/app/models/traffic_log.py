from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


class TrafficLog(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)

    source_ip: str | None = Field(default=None, index=True)
    source_port: int | None = Field(default=None)
    destination_ip: str | None = Field(default=None, index=True)
    destination_port: int | None = Field(default=None)

    predicted_label: str = Field(index=True)
    probability: float = Field(index=True)
    is_attack: bool = Field(index=True)

    action: str = Field(index=True)
    status: str = Field(index=True)
    reason: str

    probabilities: dict[str, float] = Field(default_factory=dict, sa_column=Column(JSON))
    raw_features: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    notes: str | None = None
