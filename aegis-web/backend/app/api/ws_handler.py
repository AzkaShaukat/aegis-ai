"""ws_handler.py — WebSocket with full orchestrator integration."""

from __future__ import annotations
import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import text

from app.core.database import AsyncSessionLocal
from app.core.security import decode_token
from app.services.chat_service_ext import (
    get_primary_session, prune_messages, MAX_MESSAGES
)
from app.services.web_orchestrator import handle_web_message

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])

# ── raw SQL helpers ───────────────────────────────────────────
async def _insert_msg(sid: str, role: str, content: str,
                       structured=None, module=None, risk=None):
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            INSERT INTO messages
                (id, session_id, role, content, structured,
                 media_url, media_type, module_used, risk_level, created_at)
            VALUES
                (:id, :sid, CAST(:role AS messagerole), :content,
                 CAST(:structured AS jsonb),
                 NULL, NULL, :module, :risk, :ts)
        """), {
            "id": str(uuid.uuid4()),
            "sid": sid,
            "role": role,
            "content": content or "",
            "structured": json.dumps(structured) if structured else "null",
            "module": module,
            "risk": risk,
            "ts": datetime.now(timezone.utc),
        })
        await db.commit()


async def _count(sid: str) -> int:
    async with AsyncSessionLocal() as db:
        r = await db.execute(
            text("SELECT COUNT(*) FROM messages WHERE session_id = :sid"),
            {"sid": sid}
        )
        return r.scalar() or 0


# ── send helper ───────────────────────────────────────────────
async def _send(ws: WebSocket, data: dict) -> bool:
    try:
        await ws.send_text(json.dumps(data, default=str))
        return True
    except Exception:
        return False


# ── Media loading from uploads directory ──────────────────────
async def _load_media(media_id: str) -> tuple[bytes | None, str | None]:
    """Return (file_bytes, file_type) or (None, None)."""
    import pathlib as pl

    # Possible upload directories – adjust as needed
    search_dirs = [
        pl.Path("uploads"),
        pl.Path(__file__).parent.parent.parent / "uploads",
    ]
    for base in search_dirs:
        if not base.exists():
            continue
        for ext in ["jpg", "jpeg", "png", "gif", "webp", "mp4", "mov", "avi", "mkv"]:
            f = base / f"{media_id}.{ext}"
            if f.exists():
                file_bytes = f.read_bytes()
                file_type = "video" if ext in ("mp4", "mov", "avi", "mkv") else "image"
                return file_bytes, file_type
    return None, None


# ── WebSocket handler ─────────────────────────────────────────
@router.websocket("/ws/chat")
async def ws_chat(
    websocket: WebSocket,
    token: str = Query(default=""),
    guest: str = Query(default=""),
):
    logger.info("WS attempt: token=%s guest=%s", bool(token), bool(guest))
    is_guest, user_id = False, ""

    if token:
        payload = decode_token(token)
        if not payload or payload.get("type") != "access":
            await websocket.close(code=4001, reason="Bad token")
            return
        user_id = payload.get("sub", "")
        if not user_id:
            await websocket.close(code=4001, reason="No sub")
            return
    else:
        is_guest = True
        user_id = f"guest-{uuid.uuid4().hex[:8]}"

    await websocket.accept()
    logger.info("WS ✅ %s (guest=%s)", user_id[:16], is_guest)

    # Load primary session for authenticated users
    primary_sid = None
    if not is_guest:
        async with AsyncSessionLocal() as db:
            primary_sid = await get_primary_session(db, uuid.UUID(user_id))
            await prune_messages(db, primary_sid)
        await _send(websocket, {"type": "session", "session_id": primary_sid})

    try:
        while True:
            try:
                raw = await websocket.receive_text()
            except WebSocketDisconnect:
                break

            try:
                msg = json.loads(raw)
            except Exception:
                await _send(websocket, {"type": "error", "content": "Invalid JSON"})
                continue

            if msg.get("type") == "ping":
                await _send(websocket, {"type": "pong"})
                continue

            content = (msg.get("content") or "").strip()
            media_id = msg.get("media_id") or None
            if not content and not media_id:
                continue

            sid = primary_sid if not is_guest else f"guest-{user_id}"

            # Soft cap check – prune if too many messages
            if not is_guest and sid:
                cnt = await _count(sid)
                if cnt >= MAX_MESSAGES:
                    async with AsyncSessionLocal() as db:
                        await prune_messages(db, sid)

            # Save user message (if authenticated)
            if not is_guest and sid:
                try:
                    await _insert_msg(
                        sid,
                        "user",
                        content or f"[media:{media_id[:8] if media_id else '?'}]"
                    )
                except Exception as e:
                    logger.error("Save user msg: %s", e)

            bot_id = str(uuid.uuid4())
            final = None

            # Load media bytes if present
            media_bytes, media_type = None, None
            if media_id:
                media_bytes, media_type = await _load_media(media_id)
                if not media_bytes:
                    await _send(websocket, {
                        "type": "error",
                        "content": "Could not find the uploaded file. Please try again."
                    })
                    continue

            # Call orchestrator (streams thinking + final result)
                        # Call orchestrator (streams thinking + final result)
            try:
                async for ev in handle_web_message(
                    user_id=user_id,
                    session_id=sid or str(uuid.uuid4()),
                    message_id=bot_id,
                    text=content,
                    media_bytes=media_bytes,
                    media_type=media_type,
                ):
                    await _send(websocket, ev)
                    if ev.get("type") == "result":
                        final = ev
            except Exception as e:
                logger.error("Orchestrator error: %s", e, exc_info=True)
                final = {
                    "type": "result",
                    "session_id": sid or bot_id,
                    "message_id": bot_id,
                    "module": "help",
                    "content": "⚠️ Analysis services offline. Ask cybersecurity questions directly!",
                }
                await _send(websocket, final)

            # Save bot reply (if authenticated)
            if final and not is_guest and sid:
                try:
                    await _insert_msg(
                        sid,
                        "bot",
                        final.get("content", ""),
                        structured=final.get("structured"),
                        module=final.get("module"),
                        risk=final.get("risk_level"),
                    )
                except Exception as e:
                    logger.error("Save bot reply: %s", e)

            # ── ADD THIS ──────────────────────────────────────
            # Send reload event if the orchestrator requested it
            if final and final.get("reload"):
                await _send(websocket, {"type": "reload"})

                
    except WebSocketDisconnect:
        logger.info("WS disconnected: %s", user_id[:16])
    except Exception as e:
        logger.error("WS crash [%s]: %s", user_id[:16], e, exc_info=True)
        try:
            await _send(websocket, {"type": "error", "content": "Server error. Please refresh."})
        except Exception:
            pass