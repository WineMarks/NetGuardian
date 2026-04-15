from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from app.api.deps import require_admin
from app.api.schemas import ErrorResponse
from app.models.user import User
from app.services.collector_daemon import CollectorConfig, collector_daemon

router = APIRouter(prefix="/collector", tags=["collector"])

ERROR_RESPONSES = {
    400: {"description": "Invalid request", "model": ErrorResponse},
    403: {"description": "Forbidden", "model": ErrorResponse},
    409: {"description": "Invalid state", "model": ErrorResponse},
}


@router.post(
    "/start",
    responses=ERROR_RESPONSES,
    summary="Start CICFlowMeter collector daemon (admin only)",
)
def start_collector(
    payload: dict[str, Any] = Body(
        default={
            "csv_dir": "/tmp/cicflow",
            "file_glob": "*.csv",
            "poll_seconds": 1.0,
            "max_retries": 3,
            "enable_cfm_capture": False,
            "cfm_binary": "/home/meta/master_pieces/NetGuardian/CICFlowMeter-4.0/bin/cfm",
            "tcpdump_binary": "/usr/bin/tcpdump",
            "network_interface": "eth0",
            "capture_filter": "",
            "pcap_dir": "/tmp/cicflow/pcap",
            "pcap_glob": "*.pcap",
            "rotate_seconds": 30,
            "cleanup_on_stop": True,
            "ignore_local_source": False,
        }
    ),
    _: User = Depends(require_admin),
) -> dict[str, Any]:
    csv_file = payload.get("csv_file")
    csv_dir = payload.get("csv_dir")
    file_glob = str(payload.get("file_glob", "*.csv"))
    poll_seconds = float(payload.get("poll_seconds", 1.0))
    max_retries = int(payload.get("max_retries", 3))
    enable_cfm_capture = bool(payload.get("enable_cfm_capture", False))
    cfm_binary = str(payload.get("cfm_binary", "/home/meta/master_pieces/NetGuardian/CICFlowMeter-4.0/bin/cfm"))
    tcpdump_binary = str(payload.get("tcpdump_binary", "/usr/bin/tcpdump"))
    network_interface = payload.get("network_interface")
    capture_filter = payload.get("capture_filter")
    pcap_dir = payload.get("pcap_dir")
    pcap_glob = str(payload.get("pcap_glob", "*.pcap"))
    rotate_seconds = int(payload.get("rotate_seconds", 30))
    cleanup_on_stop = bool(payload.get("cleanup_on_stop", True))
    ignore_local_source = bool(payload.get("ignore_local_source", False))

    if not csv_file and not csv_dir:
        raise HTTPException(status_code=400, detail={"code": "INVALID_INPUT", "message": "csv_file or csv_dir required"})

    try:
        collector_daemon.start(
            CollectorConfig(
                csv_file=str(csv_file) if csv_file else None,
                csv_dir=str(csv_dir) if csv_dir else None,
                file_glob=file_glob,
                poll_seconds=max(0.2, poll_seconds),
                max_retries=max(0, max_retries),
                enable_cfm_capture=enable_cfm_capture,
                cfm_binary=cfm_binary,
                tcpdump_binary=tcpdump_binary,
                network_interface=str(network_interface) if network_interface else None,
                capture_filter=str(capture_filter).strip() if capture_filter else None,
                pcap_dir=str(pcap_dir) if pcap_dir else None,
                pcap_glob=pcap_glob,
                rotate_seconds=max(2, rotate_seconds),
                cleanup_on_stop=cleanup_on_stop,
                ignore_local_source=ignore_local_source,
            )
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail={"code": "INVALID_STATE", "message": str(exc)}) from exc

    return collector_daemon.status()


@router.post(
    "/stop",
    responses=ERROR_RESPONSES,
    summary="Stop CICFlowMeter collector daemon (admin only)",
)
def stop_collector(_: User = Depends(require_admin)) -> dict[str, Any]:
    collector_daemon.stop()
    return collector_daemon.status()


@router.post(
    "/retry",
    responses=ERROR_RESPONSES,
    summary="Force retry queued failed payloads (admin only)",
)
def retry_collector(_: User = Depends(require_admin)) -> dict[str, Any]:
    count = collector_daemon.retry_failed()
    status = collector_daemon.status()
    status["retry_triggered"] = count
    return status


@router.get(
    "/status",
    responses=ERROR_RESPONSES,
    summary="Get collector daemon status and throughput (admin only)",
)
def collector_status(_: User = Depends(require_admin)) -> dict[str, Any]:
    return collector_daemon.status()


@router.get(
    "/interfaces",
    responses=ERROR_RESPONSES,
    summary="List available network interfaces (admin only)",
)
def list_network_interfaces(_: User = Depends(require_admin)) -> dict[str, Any]:
    interfaces: list[dict[str, Any]] = []

    for _, name in socket.if_nameindex():
        operstate = "unknown"
        state_file = Path("/sys/class/net") / name / "operstate"
        if state_file.exists():
            try:
                operstate = state_file.read_text(encoding="utf-8").strip()
            except OSError:
                operstate = "unknown"

        interfaces.append(
            {
                "name": name,
                "is_loopback": name == "lo",
                "is_up": operstate == "up",
                "operstate": operstate,
            }
        )

    interfaces.sort(key=lambda item: (not item["is_up"], item["is_loopback"], item["name"]))
    return {"interfaces": interfaces}
