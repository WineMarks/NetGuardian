from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class TrafficMetadata(BaseModel):
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None


class TrafficAnalyzeRequest(BaseModel):
    flow_features: dict[str, Any] = Field(default_factory=dict)
    metadata: TrafficMetadata | None = None


class TrafficAnalyzeResponse(BaseModel):
    log_id: int
    predicted_label: str
    probability: float
    is_attack: bool
    action: str
    status: str
    reason: str


class TrafficSimulateRequest(BaseModel):
    attack_label: str = "DDoS"
    probability: float = 0.9
    source_ip: str | None = "198.51.100.10"
    source_port: int | None = 45123
    destination_ip: str | None = "10.0.0.2"
    destination_port: int | None = 443
    notes: str | None = "Synthetic test event injected by operator."


class TrafficReviewRequest(BaseModel):
    decision: Literal["block", "ignore"]
    notes: str | None = None
    list_action: Literal["none", "blacklist", "graylist"] = "none"
    gray_duration_minutes: int | None = None


class TrafficLogResponse(BaseModel):
    id: int
    created_at: datetime
    source_ip: str | None
    source_port: int | None
    destination_ip: str | None
    destination_port: int | None
    predicted_label: str
    probability: float
    is_attack: bool
    action: str
    status: str
    reason: str
    probabilities: dict[str, float]
    notes: str | None


class TrafficSummaryResponse(BaseModel):
    total: int
    attacks: int
    benign: int
    blocked: int
    pending_review: int
    allowed: int


class GeoPathPoint(BaseModel):
    ip: str
    latitude: float
    longitude: float
    country: str | None = None
    city: str | None = None


class GeoPathResponse(BaseModel):
    log_id: int
    label: str
    severity: float
    created_at: datetime
    source: GeoPathPoint
    target: GeoPathPoint


class ThreatProfileResponse(BaseModel):
    source_ip: str
    total_hits: int
    attack_hits: int
    blocked_hits: int
    pending_hits: int
    first_seen: datetime
    last_seen: datetime
    top_labels: list[str]
    list_status: str
    suggestion: str


class MergedAlertCaseResponse(BaseModel):
    source_ip: str
    predicted_label: str
    case_size: int
    first_seen: datetime
    last_seen: datetime
    max_probability: float
    avg_probability: float
    status: str


class MergedAlertReviewRequest(BaseModel):
    source_ip: str
    predicted_label: str
    window_minutes: int = Field(default=15, ge=1, le=24 * 60)
    decision: Literal["block", "ignore"]
    notes: str | None = None
    list_action: Literal["none", "blacklist", "graylist"] = "none"
    gray_duration_minutes: int | None = None


class IpListEntryResponse(BaseModel):
    id: int
    created_at: datetime
    updated_at: datetime
    ip: str
    list_type: Literal["blacklist", "graylist"]
    reason: str | None
    expires_at: datetime | None
    created_by: str | None


class IpListUpsertRequest(BaseModel):
    ip: str
    list_type: Literal["blacklist", "graylist"]
    reason: str | None = None
    gray_duration_minutes: int | None = None
    expires_at: datetime | None = None


class IpListUpdateRequest(BaseModel):
    list_type: Literal["blacklist", "graylist"] | None = None
    reason: str | None = None
    gray_duration_minutes: int | None = None
    expires_at: datetime | None = None


class ErrorResponse(BaseModel):
    code: str
    message: str
    detail: str | None = None


class WebSocketEvent(BaseModel):
    event: str
    payload: dict[str, Any]
    timestamp: datetime


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)
    role: Literal["user", "admin"] = "user"
    admin_code: str | None = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)


class UserProfileResponse(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserProfileResponse


class AdminUserUpdateRequest(BaseModel):
    role: Literal["user", "admin"] | None = None
    is_active: bool | None = None


class NotificationBindingResponse(BaseModel):
    webhook_url: str | None
    webhook_enabled: bool
    notify_email: str | None
    notify_email_verified: bool
    pending_email: str | None
    urgent_threshold: float


class WebhookBindRequest(BaseModel):
    webhook_url: str | None = None
    enabled: bool = True


class EmailCodeSendRequest(BaseModel):
    email: str


class EmailCodeVerifyRequest(BaseModel):
    email: str
    code: str = Field(min_length=4, max_length=8)
