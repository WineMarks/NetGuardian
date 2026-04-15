from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import WebSocket


class EventBus:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(websocket)

    async def broadcast(self, event: str, payload: dict) -> None:
        message = {
            "event": event,
            "payload": payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        async with self._lock:
            clients = list(self._clients)

        dead_clients: list[WebSocket] = []
        for client in clients:
            try:
                await client.send_json(message)
            except Exception:  # noqa: BLE001
                dead_clients.append(client)

        if dead_clients:
            async with self._lock:
                for client in dead_clients:
                    self._clients.discard(client)


event_bus = EventBus()
