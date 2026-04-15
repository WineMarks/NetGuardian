from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib import error, request

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.api.deps import get_current_user
from app.core.config import Settings, get_settings
from app.core.database import get_session
from app.models.user import User

router = APIRouter(prefix="/chat", tags=["chat"])


class ChatMessage(BaseModel):
    role: str = Field(pattern="^(system|user|assistant)$")
    content: str = Field(min_length=1, max_length=4000)


class ChatCompletionRequest(BaseModel):
    messages: list[ChatMessage]
    model: str | None = None
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)


class ChatCompletionResponse(BaseModel):
    message: str
    model: str


class ChatApiKeyBindRequest(BaseModel):
    api_key: str = Field(min_length=10, max_length=256)


class ChatApiKeyStatusResponse(BaseModel):
    configured: bool
    masked_key: str | None = None


class ChatDebugStreamRequest(BaseModel):
    text: str = Field(default="这是一段用于验证流式输出的调试文本。若你逐字看到这句话，说明前端渲染和后端SSE链路都正常。")
    delay_ms: int = Field(default=120, ge=30, le=2000)


def _mask_api_key(raw: str | None) -> str | None:
    if not raw:
        return None
    if len(raw) <= 10:
        return "*" * len(raw)
    return f"{raw[:6]}...{raw[-4:]}"


def _build_upstream_payload(payload: ChatCompletionRequest, settings: Settings) -> tuple[str, dict[str, Any]]:
    model_name = (payload.model or settings.deepseek_model).strip() or settings.deepseek_model
    outbound_messages = [m.model_dump() for m in payload.messages]
    has_system = any((m.get("role") == "system") for m in outbound_messages)
    if not has_system:
        outbound_messages = [
            {
                "role": "system",
                "content": settings.deepseek_system_prompt,
            },
            *outbound_messages,
        ]

    upstream_payload: dict[str, Any] = {
        "model": model_name,
        "messages": outbound_messages,
        "temperature": payload.temperature,
    }
    return model_name, upstream_payload


@router.post("/completions", response_model=ChatCompletionResponse)
def chat_completions(
    payload: ChatCompletionRequest = Body(...),
    current_user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> ChatCompletionResponse:
    if not current_user.chat_api_key:
        raise HTTPException(status_code=400, detail={"code": "INVALID_INPUT", "message": "请先在个人中心绑定你的 API Key"})

    model_name, upstream_payload = _build_upstream_payload(payload, settings)

    endpoint = f"{settings.deepseek_base_url.rstrip('/')}/chat/completions"
    req = request.Request(
        url=endpoint,
        data=json.dumps(upstream_payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {current_user.chat_api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with request.urlopen(req, timeout=float(settings.deepseek_timeout_seconds)) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=502, detail={"code": "UPSTREAM_ERROR", "message": f"模型服务调用失败: {detail}"}) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail={"code": "UPSTREAM_ERROR", "message": "模型服务连接失败"}) from exc

    content = (
        body.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
        .strip()
    )
    if not content:
        raise HTTPException(status_code=502, detail={"code": "UPSTREAM_ERROR", "message": "模型未返回有效内容"})

    return ChatCompletionResponse(message=content, model=model_name)


@router.post("/completions/stream")
def chat_completions_stream(
    payload: ChatCompletionRequest = Body(...),
    current_user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> StreamingResponse:
    if not current_user.chat_api_key:
        raise HTTPException(status_code=400, detail={"code": "INVALID_INPUT", "message": "请先在个人中心绑定你的 API Key"})

    _, upstream_payload = _build_upstream_payload(payload, settings)
    upstream_payload["stream"] = True

    endpoint = f"{settings.deepseek_base_url.rstrip('/')}/chat/completions"
    req = request.Request(
        url=endpoint,
        data=json.dumps(upstream_payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {current_user.chat_api_key}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        },
        method="POST",
    )

    try:
        upstream_resp = request.urlopen(req, timeout=float(settings.deepseek_timeout_seconds))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=502, detail={"code": "UPSTREAM_ERROR", "message": f"模型服务调用失败: {detail}"}) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail={"code": "UPSTREAM_ERROR", "message": "模型服务连接失败"}) from exc

    def event_stream():
        done_sent = False
        with upstream_resp as resp:
            for raw_line in resp:
                if not raw_line:
                    continue
                line = raw_line.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                if line.startswith("data:"):
                    yield f"{line}\n\n"
                    if line.strip() == "data: [DONE]":
                        done_sent = True
                else:
                    yield f"data: {line}\n\n"
        if not done_sent:
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/key", response_model=ChatApiKeyStatusResponse)
def get_my_chat_key_status(current_user: User = Depends(get_current_user)) -> ChatApiKeyStatusResponse:
    return ChatApiKeyStatusResponse(
        configured=bool(current_user.chat_api_key),
        masked_key=_mask_api_key(current_user.chat_api_key),
    )


@router.put("/key", response_model=ChatApiKeyStatusResponse)
def bind_my_chat_key(
    payload: ChatApiKeyBindRequest = Body(...),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> ChatApiKeyStatusResponse:
    current_user.chat_api_key = payload.api_key.strip()
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return ChatApiKeyStatusResponse(
        configured=bool(current_user.chat_api_key),
        masked_key=_mask_api_key(current_user.chat_api_key),
    )


@router.delete("/key", response_model=ChatApiKeyStatusResponse)
def clear_my_chat_key(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> ChatApiKeyStatusResponse:
    current_user.chat_api_key = None
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return ChatApiKeyStatusResponse(configured=False, masked_key=None)


@router.post("/completions/stream-debug")
async def chat_completions_stream_debug(
    payload: ChatDebugStreamRequest = Body(default=ChatDebugStreamRequest()),
    _: User = Depends(get_current_user),
) -> StreamingResponse:
    async def event_stream():
        yield 'data: {"debug":"stream-debug-start"}\n\n'
        for ch in payload.text:
            chunk = {
                "choices": [
                    {
                        "delta": {"content": ch},
                    }
                ]
            }
            yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
            await asyncio.sleep(payload.delay_ms / 1000)
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
