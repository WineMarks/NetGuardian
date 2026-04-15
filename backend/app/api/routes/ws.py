from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.config import get_settings
from app.services.security import decode_access_token
from app.services.event_bus import event_bus

router = APIRouter(prefix="/ws", tags=["ws"])


@router.websocket("/events")
async def websocket_events(websocket: WebSocket) -> None:
    settings = get_settings()
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008, reason="Missing token")
        return

    try:
        decode_access_token(token, settings)
    except Exception:  # noqa: BLE001
        await websocket.close(code=1008, reason="Invalid token")
        return

    await event_bus.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await event_bus.disconnect(websocket)
