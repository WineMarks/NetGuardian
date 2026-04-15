from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from app.api.deps import get_current_user, get_traffic_service, require_admin
from app.api.schemas import (
    ErrorResponse,
    GeoPathResponse,
    MergedAlertCaseResponse,
    MergedAlertReviewRequest,
    ThreatProfileResponse,
    TrafficAnalyzeRequest,
    TrafficAnalyzeResponse,
    TrafficLogResponse,
    TrafficReviewRequest,
    TrafficSimulateRequest,
    TrafficSummaryResponse,
)
from app.core.exceptions import AppError
from app.models.traffic_log import TrafficLog
from app.models.user import User
from app.services.event_bus import event_bus
from app.services.model_runtime import model_runtime
from app.services.traffic_service import AnalyzeInput, TrafficService

router = APIRouter(prefix="/traffic", tags=["traffic"])

ERROR_RESPONSES = {
    400: {
        "description": "Invalid request",
        "model": ErrorResponse,
    },
    404: {
        "description": "Resource not found",
        "model": ErrorResponse,
    },
    409: {
        "description": "Invalid state",
        "model": ErrorResponse,
    },
    500: {
        "description": "Internal server error",
        "model": ErrorResponse,
    },
}


def to_error_detail(*, code: str, message: str, detail: str | None = None) -> dict[str, Any]:
    return ErrorResponse(code=code, message=message, detail=detail).model_dump()


def to_log_response(log: TrafficLog) -> TrafficLogResponse:
    return TrafficLogResponse(
        id=int(log.id),
        created_at=log.created_at,
        source_ip=log.source_ip,
        source_port=log.source_port,
        destination_ip=log.destination_ip,
        destination_port=log.destination_port,
        predicted_label=log.predicted_label,
        probability=log.probability,
        is_attack=log.is_attack,
        action=log.action,
        status=log.status,
        reason=log.reason,
        probabilities=log.probabilities,
        notes=log.notes,
    )


@router.post(
    "/analyze",
    response_model=TrafficAnalyzeResponse,
    responses=ERROR_RESPONSES,
    summary="Analyze one traffic flow",
)
async def analyze_traffic(
    payload: TrafficAnalyzeRequest = Body(
        ...,
        examples=[
            {
                "summary": "HTTPS normal flow",
                "value": {
                    "flow_features": {
                        "Destination Port": 443,
                        "Flow Duration": 18000,
                        "Total Fwd Packets": 12,
                        "Total Backward Packets": 8,
                    },
                    "metadata": {
                        "source_ip": "10.0.0.8",
                        "source_port": 51515,
                        "destination_ip": "10.0.0.2",
                        "destination_port": 443,
                    },
                },
            }
        ],
    ),
    traffic_service: TrafficService = Depends(get_traffic_service),
    _: User = Depends(get_current_user),
) -> TrafficAnalyzeResponse:
    metadata = payload.metadata or None
    analyze_input = AnalyzeInput(
        flow_features=payload.flow_features,
        source_ip=metadata.source_ip if metadata else None,
        source_port=metadata.source_port if metadata else None,
        destination_ip=metadata.destination_ip if metadata else None,
        destination_port=metadata.destination_port if metadata else None,
    )

    try:
        log = traffic_service.analyze(analyze_input)
    except AppError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=to_error_detail(code=exc.code, message=exc.message),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=500,
            detail=to_error_detail(code="INTERNAL_ERROR", message="Analyze failed", detail=str(exc)),
        ) from exc

    await event_bus.broadcast("traffic.analyzed", to_log_response(log).model_dump(mode="json"))

    return TrafficAnalyzeResponse(
        log_id=int(log.id),
        predicted_label=log.predicted_label,
        probability=log.probability,
        is_attack=log.is_attack,
        action=log.action,
        status=log.status,
        reason=log.reason,
    )


@router.post(
    "/simulate",
    response_model=TrafficAnalyzeResponse,
    responses=ERROR_RESPONSES,
    summary="Inject synthetic attack event (bypass model)",
)
async def simulate_attack(
    payload: TrafficSimulateRequest = Body(
        ...,
        examples=[
            {
                "summary": "Manual review synthetic attack",
                "value": {
                    "attack_label": "DDoS",
                    "probability": 0.9,
                    "source_ip": "203.0.113.40",
                    "source_port": 51321,
                    "destination_ip": "10.0.0.2",
                    "destination_port": 443,
                    "notes": "Synthetic pending review event for workflow testing.",
                },
            },
            {
                "summary": "Auto-block synthetic attack",
                "value": {
                    "attack_label": "PortScan",
                    "probability": 0.99,
                    "source_ip": "198.51.100.66",
                    "source_port": 42111,
                    "destination_ip": "10.0.0.2",
                    "destination_port": 22,
                    "notes": "Synthetic auto block event for dashboard testing.",
                },
            },
        ],
    ),
    traffic_service: TrafficService = Depends(get_traffic_service),
    _: User = Depends(require_admin),
) -> TrafficAnalyzeResponse:
    try:
        log = traffic_service.simulate_attack(
            attack_label=payload.attack_label,
            probability=payload.probability,
            source_ip=payload.source_ip,
            source_port=payload.source_port,
            destination_ip=payload.destination_ip,
            destination_port=payload.destination_port,
            notes=payload.notes,
        )
    except AppError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=to_error_detail(code=exc.code, message=exc.message),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=500,
            detail=to_error_detail(code="INTERNAL_ERROR", message="Simulation failed", detail=str(exc)),
        ) from exc

    await event_bus.broadcast("traffic.simulated", to_log_response(log).model_dump(mode="json"))

    return TrafficAnalyzeResponse(
        log_id=int(log.id),
        predicted_label=log.predicted_label,
        probability=log.probability,
        is_attack=log.is_attack,
        action=log.action,
        status=log.status,
        reason=log.reason,
    )


@router.post(
    "/{log_id}/review",
    response_model=TrafficLogResponse,
    responses=ERROR_RESPONSES,
    summary="Review pending traffic decision",
)
async def review_traffic(
    log_id: int,
    payload: TrafficReviewRequest = Body(
        ...,
        examples=[
            {
                "summary": "Approve block",
                "value": {
                    "decision": "block",
                    "notes": "Confirmed malicious scanning behavior.",
                    "list_action": "blacklist",
                },
            },
            {
                "summary": "Ignore alert",
                "value": {
                    "decision": "ignore",
                    "notes": "False positive caused by stress test.",
                },
            },
        ],
    ),
    traffic_service: TrafficService = Depends(get_traffic_service),
    _: User = Depends(get_current_user),
) -> TrafficLogResponse:
    try:
        log = traffic_service.review(
            log_id=log_id,
            decision=payload.decision,
            notes=payload.notes,
            list_action=payload.list_action,
            gray_duration_minutes=payload.gray_duration_minutes,
            operator=_.username,
        )
    except AppError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=to_error_detail(code=exc.code, message=exc.message),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=500,
            detail=to_error_detail(code="INTERNAL_ERROR", message="Review failed", detail=str(exc)),
        ) from exc

    await event_bus.broadcast("traffic.reviewed", to_log_response(log).model_dump(mode="json"))

    return to_log_response(log)


@router.get(
    "/logs",
    response_model=list[TrafficLogResponse],
    summary="List recent traffic logs",
)
def list_recent_logs(
    limit: int = Query(default=100, ge=1, le=1000),
    status: str | None = Query(default=None),
    action: str | None = Query(default=None),
    label: str | None = Query(default=None),
    traffic_service: TrafficService = Depends(get_traffic_service),
    _: User = Depends(get_current_user),
) -> list[TrafficLogResponse]:
    logs = traffic_service.list_filtered(limit=limit, status=status, action=action, label=label)
    return [to_log_response(log) for log in logs]


@router.get(
    "/summary",
    response_model=TrafficSummaryResponse,
    summary="Get traffic lifecycle summary",
)
def traffic_summary(
    traffic_service: TrafficService = Depends(get_traffic_service),
    _: User = Depends(get_current_user),
) -> TrafficSummaryResponse:
    return TrafficSummaryResponse(**traffic_service.get_summary())


@router.get(
    "/geo-paths",
    response_model=list[GeoPathResponse],
    summary="Get geo attack paths for map visualization",
)
def get_geo_paths(
    minutes: int = Query(default=60, ge=1, le=24 * 60),
    limit: int = Query(default=300, ge=1, le=2000),
    traffic_service: TrafficService = Depends(get_traffic_service),
    _: User = Depends(get_current_user),
) -> list[GeoPathResponse]:
    rows = traffic_service.get_geo_paths(minutes=minutes, limit=limit)
    return [GeoPathResponse.model_validate(row) for row in rows]


@router.get(
    "/threat-profiles",
    response_model=list[ThreatProfileResponse],
    summary="Get high frequency source IP threat profiles",
)
def get_threat_profiles(
    minutes: int = Query(default=120, ge=1, le=24 * 60),
    limit: int = Query(default=20, ge=1, le=200),
    traffic_service: TrafficService = Depends(get_traffic_service),
    _: User = Depends(get_current_user),
) -> list[ThreatProfileResponse]:
    rows = traffic_service.get_threat_profiles(minutes=minutes, limit=limit)
    return [ThreatProfileResponse.model_validate(row) for row in rows]


@router.get(
    "/merged-cases",
    response_model=list[MergedAlertCaseResponse],
    summary="List merged alert cases for noise reduction center",
)
def get_merged_cases(
    window_minutes: int = Query(default=15, ge=1, le=24 * 60),
    limit: int = Query(default=100, ge=1, le=1000),
    traffic_service: TrafficService = Depends(get_traffic_service),
    _: User = Depends(get_current_user),
) -> list[MergedAlertCaseResponse]:
    rows = traffic_service.get_merged_cases(window_minutes=window_minutes, limit=limit)
    return [MergedAlertCaseResponse.model_validate(row) for row in rows]


@router.post(
    "/merged-cases/review",
    summary="Review merged alert case in bulk",
)
def review_merged_case(
    payload: MergedAlertReviewRequest,
    traffic_service: TrafficService = Depends(get_traffic_service),
    user: User = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        return traffic_service.review_merged_case(
            source_ip=payload.source_ip,
            predicted_label=payload.predicted_label,
            window_minutes=payload.window_minutes,
            decision=payload.decision,
            notes=payload.notes,
            list_action=payload.list_action,
            gray_duration_minutes=payload.gray_duration_minutes,
            operator=user.username,
        )
    except AppError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=to_error_detail(code=exc.code, message=exc.message),
        ) from exc


@router.get(
    "/required-features",
    summary="Get model required feature columns",
)
def get_required_features(_: User = Depends(get_current_user)) -> dict[str, Any]:
    features = model_runtime.get_required_features()
    return {
        "feature_count": len(features),
        "features": features,
    }
