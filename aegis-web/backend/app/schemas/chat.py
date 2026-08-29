"""app/schemas/chat.py — Chat session and message Pydantic schemas."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


# ── Inbound WebSocket message (client → server) ───────────────────────────────

class WsInbound(BaseModel):
    type: str = "message"          # "message" | "ping"
    session_id: Optional[str] = None   # null = start new session
    content: str = ""
    media_id: Optional[str] = None     # future: after upload endpoint


# ── Outbound WebSocket events (server → client) ───────────────────────────────

class WsThinking(BaseModel):
    type: str = "thinking"
    content: str
    step: int = 1


class WsResult(BaseModel):
    type: str = "result"
    session_id: str
    message_id: str
    module: Optional[str] = None    # link | qr | credential | profile | smishing
    risk_level: Optional[str] = None
    content: str                    # human-readable text (plain, no WA markdown)
    structured: Optional[dict] = None   # full scan JSON for frontend cards
    flags: list[str] = []
    action: Optional[str] = None


class WsError(BaseModel):
    type: str = "error"
    content: str
    code: Optional[str] = None


# ── REST: Chat Sessions ───────────────────────────────────────────────────────

class SessionSummary(BaseModel):
    id: uuid.UUID
    title: str
    created_at: datetime
    updated_at: datetime
    is_archived: bool
    message_count: int = 0

    class Config:
        from_attributes = True


class SessionDetail(BaseModel):
    id: uuid.UUID
    title: str
    created_at: datetime
    updated_at: datetime
    messages: list["MessageOut"]

    class Config:
        from_attributes = True


class SessionRename(BaseModel):
    title: str


# ── REST: Messages ────────────────────────────────────────────────────────────

class MessageOut(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    role: str
    content: str
    structured: Optional[dict] = None
    module_used: Optional[str] = None
    risk_level: Optional[str] = None
    media_url: Optional[str] = None
    media_type: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
