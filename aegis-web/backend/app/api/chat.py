"""app/api/chat.py — WebSocket + REST endpoints."""
from __future__ import annotations
import base64, json, logging, uuid
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db, AsyncSessionLocal
from app.core.security import decode_token
from app.models.chat import MessageRole
from app.schemas.chat import SessionDetail, SessionRename, SessionSummary
from app.schemas.scan import ScanHistoryResponse, ScanStats
from app.services import chat_service
from app.services.web_orchestrator import handle_web_message

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])

# ── Service URLs ──────────────────────────────────────────────
_QR_URL       = "http://localhost:8001/scan-base64"
_DEEPFAKE_URL = "http://localhost:8004/analyze-base64"
_DEEPFAKE_ALT = "http://localhost:8004/analyze"          # alternate endpoint
_TIMEOUT      = httpx.Timeout(30.0, connect=3.0)         # 3s connect, 30s read


async def _safe_send(ws: WebSocket, data: dict) -> bool:
    try:
        await ws.send_text(json.dumps(data, default=str))
        return True
    except Exception:
        return False


async def _call_qr(b64: str) -> dict | None:
    """Call QR scanner microservice. Returns result dict or None."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.post(_QR_URL, json={"image_base64": b64})
            if r.status_code == 200:
                return r.json()
    except httpx.ConnectError:
        logger.debug("QR service not running (port 8001)")
    except Exception as e:
        logger.debug("QR error: %s", e)
    return None


async def _call_deepfake(file_bytes: bytes) -> dict | None:
    """Call deepfake API: POST /analyze/image (multipart file upload)."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.post(
                "http://localhost:8004/analyze/image",
                files={"file": ("image.jpg", file_bytes, "image/jpeg")},
            )
            if r.status_code == 200:
                d = r.json()
                logger.info("✅ Deepfake verdict=%s risk=%s prob=%.0f%%",
                    d.get("verdict","?"), d.get("overall_risk_level","?"),
                    float(d.get("ensemble_probability", d.get("confidence",0)))*100)
                return d
            logger.warning("Deepfake /analyze/image: HTTP %d — %s", r.status_code, r.text[:100])
    except httpx.ConnectError:
        logger.debug("Deepfake service not running (port 8004)")
    except Exception as exc:
        logger.error("Deepfake /analyze/image error: %s | type: %s", exc, type(exc).__name__)
    return None


async def _handle_media(media_id: str, ws: WebSocket, sid: str, bot_id: str) -> dict:
    """Analyse uploaded image/video. Reads file from disk directly."""
    import pathlib

    # Find the uploaded file on disk
    file_bytes = None
    file_type  = "image"

    for upload_dir in [
        pathlib.Path("uploads"),
        pathlib.Path(__file__).parent.parent.parent / "uploads",
        pathlib.Path("backend/uploads"),
    ]:
        if not upload_dir.exists():
            continue
        for ext in ["jpg","jpeg","png","gif","webp","mp4","mov","avi"]:
            candidate = upload_dir / f"{media_id}.{ext}"
            if candidate.exists():
                file_bytes = candidate.read_bytes()
                file_type  = "video" if ext in ("mp4","mov","avi") else "image"
                logger.info("Media found: %s (%d bytes)", candidate.name, len(file_bytes))
                break
        if file_bytes:
            break

    if not file_bytes:
        # Fallback: try get_media_bytes if it exists
        try:
            from app.api.upload import get_media_bytes
            result = await get_media_bytes(media_id)
            if result:
                file_bytes, file_type = result
        except Exception as e:
            logger.debug("get_media_bytes fallback failed: %s", e)

    if not file_bytes:
        return {
            "type": "result", "session_id": sid, "message_id": bot_id, "module": "help",
            "content": (
                f"Could not find uploaded file (id={media_id[:8]}). "
                "Please try uploading again."
            ),
        }

    await _safe_send(ws, {
        "type": "thinking", "content": f"Analysing {file_type}…", "step": 1,
    })

    # ── QR scan (images only) ─────────────────────────────────
    if file_type == "image":
        qr = await _call_qr(base64.b64encode(file_bytes).decode())
        if qr and not qr.get("module_unavailable") and qr.get("decoded_url"):
            url  = qr.get("decoded_url", "")
            risk = qr.get("risk_level", "UNKNOWN")
            return {
                "type": "result", "session_id": sid, "message_id": bot_id,
                "module": "qr", "risk_level": risk,
                "content": (
                    f"**QR code detected.**\n\n"
                    f"URL: `{url}`\n"
                    f"Risk level: **{risk}**"
                ),
                "structured": qr,
            }

    # ── Deepfake detection ────────────────────────────────────
    await _safe_send(ws, {"type": "thinking", "content": "Running deepfake detection…", "step": 2})
    df = await _call_deepfake(file_bytes)
    if df and not df.get("module_unavailable"):
        risk    = df.get("overall_risk_level", df.get("risk_level", "UNKNOWN"))
        verdict = df.get("verdict", "UNKNOWN")
        prob    = float(df.get("ensemble_probability", df.get("confidence", 0)))
        return {
            "type": "result", "session_id": sid, "message_id": bot_id,
            "module": "deepfake", "risk_level": risk,
            "content": (
                f"**Deepfake analysis complete.**\n\n"
                f"Verdict: **{verdict}**\nRisk: **{risk}**\n"
                f"AI-generated probability: {prob*100:.0f}%\n\n"
                + ("🔴 Signs of AI manipulation detected."
                   if str(verdict).upper() in ("FAKE","DEEPFAKE")
                   else "✅ Image appears authentic.")
            ),
            "structured": df,
        }

    # ── Fallback ──────────────────────────────────────────────
    return {
        "type": "result", "session_id": sid, "message_id": bot_id, "module": "help",
        "content": (
            f"Image received ({file_type}).\n\n"
            "**Deepfake Detector (port 8004)** is currently offline.\n\n"
            "**To start it:**\n"
            "```\ncd D:\\Aegis AI\\deepfake-api\npython start_deepfake.py\n```\n\n"
            "Tip: paste a URL directly for link analysis."
        ),
    }


async def ws_chat(
    websocket: WebSocket,
    token:     str = Query(default=""),
    guest:     str = Query(default=""),
):
    is_guest = False
    user_id  = ""
    if token:
        payload = decode_token(token)
        if not payload or payload.get("type") != "access":
            await websocket.close(code=4001, reason="Bad token")
            return
        user_id = payload.get("sub", "")
        if not user_id:
            await websocket.close(code=4001, reason="Bad sub")
            return
    else:
        is_guest = True
        user_id  = f"guest-{uuid.uuid4().hex[:8]}"

    await websocket.accept()
    logger.info("WS ✅ %s (guest=%s)", user_id[:16], is_guest)
    guest_sid = str(uuid.uuid4()) if is_guest else None

    try:
        while True:
            try:
                raw = await websocket.receive_text()
            except WebSocketDisconnect:
                break

            try:
                msg = json.loads(raw)
            except Exception:
                await _safe_send(websocket, {"type":"error","content":"Invalid JSON"})
                continue

            if msg.get("type") == "ping":
                await _safe_send(websocket, {"type": "pong"})
                continue

            content  = (msg.get("content") or "").strip()
            media_id = msg.get("media_id") or None
            if not content and not media_id:
                continue

            # Rate limit
            if not is_guest:
                try:
                    from app.core.config import get_settings
                    import redis.asyncio as aioredis
                    s = get_settings()
                    r = await aioredis.from_url(s.redis_rate_limit_url, decode_responses=True)
                    k = f"aegis:rl:{user_id}"
                    n = await r.incr(k)
                    if n == 1: await r.expire(k, 60)
                    if n > s.rate_limit_per_minute:
                        await _safe_send(websocket, {
                            "type":"error","content":f"Rate limit: {s.rate_limit_per_minute}/min.","code":"rate_limit",
                        })
                        continue
                except Exception:
                    pass

            # Session
            if is_guest:
                sid = guest_sid
            else:
                async with AsyncSessionLocal() as db:
                    sess = await chat_service.get_or_create_session(
                        db, uuid.UUID(user_id), msg.get("session_id")
                    )
                    await db.commit()
                    sid = str(sess.id)

            # Save user message
            if not is_guest and sid:
                async with AsyncSessionLocal() as db:
                    s2 = await chat_service.get_or_create_session(db, uuid.UUID(user_id), sid)
                    await chat_service.save_message(
                        db, s2, MessageRole.USER,
                        content=content or (f"[image: {media_id[:8]}]" if media_id else "[message]"),
                    )
                    await db.commit()

            bot_id = str(uuid.uuid4())
            final  = None

            # Route: media or text
            if media_id:
                try:
                    final = await _handle_media(media_id, websocket, sid or bot_id, bot_id)
                except Exception as exc:
                    logger.error("_handle_media crashed: %s", exc, exc_info=True)
                    final = {
                        "type":"result","session_id":sid or bot_id,"message_id":bot_id,
                        "module":"help","content":"Media analysis failed. Please try again.",
                    }
                if final:
                    await _safe_send(websocket, final)
            else:
                try:
                    async for ev in handle_web_message(
                        user_id=user_id,
                        session_id=sid or str(uuid.uuid4()),
                        message_id=bot_id,
                        text=content,
                    ):
                        await _safe_send(websocket, ev)
                        if ev.get("type") == "result":
                            final = ev
                except Exception as exc:
                    logger.error("Orchestrator error: %s", exc, exc_info=True)
                    final = {
                        "type":"result","session_id":sid or bot_id,"message_id":bot_id,
                        "module":"help","content":(
                            "Analysis services (ports 8000–8004) are offline. "
                            "I can still answer cybersecurity questions — ask me anything!"
                        ),
                    }
                    await _safe_send(websocket, final)

            # Persist bot reply
            if final and not is_guest and sid:
                try:
                    async with AsyncSessionLocal() as db:
                        s3 = await chat_service.get_or_create_session(db, uuid.UUID(user_id), sid)
                        await chat_service.save_message(
                            db, s3, MessageRole.BOT,
                            content=final.get("content",""),
                            structured=final.get("structured"),
                            module_used=final.get("module"),
                            risk_level=final.get("risk_level"),
                        )
                        mod = final.get("module","")
                        if mod and mod not in ("help","cyber_qa","system","history"):
                            await chat_service.log_scan(
                                db, uuid.UUID(user_id), mod,
                                scanned_value=(content or media_id or "")[:200],
                                verdict=final.get("risk_level","SAFE"),
                                risk_level=final.get("risk_level","SAFE"),
                            )
                        await db.commit()
                except Exception as e:
                    logger.error("Persist bot reply failed: %s", e)

    except WebSocketDisconnect:
        logger.info("WS disconnected: %s", user_id[:16])
    except Exception as e:
        logger.error("WS crash [%s]: %s", user_id[:16], e, exc_info=True)
        await _safe_send(websocket, {
            "type":"error","content":"Unexpected server error. Please refresh.",
        })

# ── REST endpoints (on the same main router) ─────────────────
from app.core.dependencies import get_current_user
from app.models.user import User
from app.schemas.chat import SessionDetail, SessionRename, SessionSummary
from app.schemas.scan import ScanHistoryResponse, ScanStats
import uuid as _uuid

@router.get("/api/chat/sessions", response_model=list[SessionSummary])
async def list_sessions(u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await chat_service.list_sessions(db, u.id)

@router.get("/api/chat/sessions/{sid}", response_model=SessionDetail)
async def get_session(sid: _uuid.UUID, u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    s = await chat_service.get_session_with_messages(db, sid, u.id)
    if not s: raise HTTPException(404, "Session not found")
    return s

@router.patch("/api/chat/sessions/{sid}", response_model=SessionSummary)
async def rename(sid: _uuid.UUID, req: SessionRename, u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    s = await chat_service.rename_session(db, sid, u.id, req.title)
    if not s: raise HTTPException(404, "Not found")
    await db.commit()
    return {"id": s.id, "title": s.title, "created_at": s.created_at,
            "updated_at": s.updated_at, "is_archived": s.is_archived, "message_count": 0}

@router.delete("/api/chat/sessions/{sid}", status_code=204)
async def delete(sid: _uuid.UUID, u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not await chat_service.archive_session(db, sid, u.id):
        raise HTTPException(404, "Not found")
    await db.commit()

@router.get("/api/history/30days", response_model=ScanHistoryResponse)
async def history(u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    e = await chat_service.get_scan_history(db, u.id, days=30)
    return {"entries": e, "total": len(e), "period_days": 30}

@router.get("/api/history/stats", response_model=ScanStats)
async def stats(u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await chat_service.get_scan_stats(db, u.id)

# Aliases so main.py can import any name it expects
chat_router    = router
history_router = router

# ── REST endpoints (on the same main router) ─────────────────
from app.core.dependencies import get_current_user
from app.models.user import User
from app.schemas.chat import SessionDetail, SessionRename, SessionSummary
from app.schemas.scan import ScanHistoryResponse, ScanStats
import uuid as _uuid

@router.get("/api/chat/sessions", response_model=list[SessionSummary])
async def list_sessions(u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await chat_service.list_sessions(db, u.id)

@router.get("/api/chat/sessions/{sid}", response_model=SessionDetail)
async def get_session(sid: _uuid.UUID, u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    s = await chat_service.get_session_with_messages(db, sid, u.id)
    if not s: raise HTTPException(404, "Session not found")
    return s

@router.patch("/api/chat/sessions/{sid}", response_model=SessionSummary)
async def rename(sid: _uuid.UUID, req: SessionRename, u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    s = await chat_service.rename_session(db, sid, u.id, req.title)
    if not s: raise HTTPException(404, "Not found")
    await db.commit()
    return {"id": s.id, "title": s.title, "created_at": s.created_at,
            "updated_at": s.updated_at, "is_archived": s.is_archived, "message_count": 0}

@router.delete("/api/chat/sessions/{sid}", status_code=204)
async def delete(sid: _uuid.UUID, u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not await chat_service.archive_session(db, sid, u.id):
        raise HTTPException(404, "Not found")
    await db.commit()

@router.get("/api/history/30days", response_model=ScanHistoryResponse)
async def history(u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    e = await chat_service.get_scan_history(db, u.id, days=30)
    return {"entries": e, "total": len(e), "period_days": 30}

@router.get("/api/history/stats", response_model=ScanStats)
async def stats(u: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    return await chat_service.get_scan_stats(db, u.id)

# Aliases so main.py can import any name it expects
chat_router    = router
history_router = router
