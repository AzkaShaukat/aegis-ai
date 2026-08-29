"""app/main.py — Aegis Orchestra Service (Port 8006)."""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

from app.config import get_settings
from app.whatsapp.client import (
    verify_webhook, verify_signature, parse_incoming,
    send_text, send_buttons, send_image_url, mark_read,
)
from app.handlers.orchestrator import handle_message
from app.session import get_redis
from app.router.ollama_client import is_ollama_available
from app.router.health_check import check_all_modules

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🛡️  Aegis Orchestra starting on port %d", settings.orchestra_port)
    try:
        r = await get_redis()
        await r.ping()
        logger.info("✅ Redis connected")
    except Exception as e:
        logger.warning("⚠️  Redis not available: %s", e)
    ollama_ok = await is_ollama_available()
    if ollama_ok:
        logger.info("✅ Ollama available (%s)", settings.ollama_model)
    else:
        logger.warning("⚠️  Ollama not reachable — human explanations disabled")

    # Check all module connectivity — logs clear errors if any are unreachable
    await check_all_modules()

    logger.info("📡 Webhook: %s/webhook", settings.public_url)
    yield
    logger.info("🛡️  Orchestra shutting down")


app = FastAPI(
    title="Aegis AI — WhatsApp Orchestra",
    version="1.0.0",
    lifespan=lifespan,
)


# ── Webhook verification (GET) ────────────────────────────────────────────────

@app.get("/webhook")
async def webhook_verify(request: Request):
    params    = request.query_params
    mode      = params.get("hub.mode", "")
    token     = params.get("hub.verify_token", "")
    challenge = params.get("hub.challenge", "")
    result = verify_webhook(mode, token, challenge)
    if result:
        logger.info("✅ Webhook verified by Meta")
        return PlainTextResponse(result)
    logger.warning("❌ Webhook verification failed")
    raise HTTPException(status_code=403, detail="Webhook verification failed")


# ── Incoming messages (POST) ──────────────────────────────────────────────────

@app.post("/webhook")
async def webhook_receive(request: Request):
    body_bytes = await request.body()

    sig = request.headers.get("X-Hub-Signature-256", "")
    if not verify_signature(body_bytes, sig):
        raise HTTPException(status_code=403, detail="Invalid signature")

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"status": "ok"}, status_code=200)

    # Filter: skip pure status updates (delivered/read receipts, system events)
    # These arrive as entries with only "statuses" key — no "messages" key
    for entry in body.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            # Skip if no messages (status updates, etc.)
            if "messages" not in value:
                continue

    messages = parse_incoming(body)
    if not messages:
        return JSONResponse({"status": "ok"}, status_code=200)

    for msg in messages:
        phone      = msg["from_number"]
        text       = msg["text"]
        msg_type   = msg["type"]
        message_id = msg["message_id"]
        media_id   = msg.get("media_id", "")

        if not phone:
            continue

        # Redis-based dedup (more reliable than in-memory across restarts)
        if message_id:
            try:
                r = await get_redis()
                dedup_key = f"aegis:dedup:{message_id}"
                already_seen = await r.set(dedup_key, "1", ex=120, nx=True)
                if not already_seen:
                    logger.debug("Duplicate message skipped (Redis): %s", message_id)
                    continue
            except Exception:
                pass  # Redis down — fall through to in-memory dedup in client.py

        logger.info("📩 [%s] type=%s text=%s", phone, msg_type, repr(text[:60]))
        await mark_read(message_id)

        media_type = None
        if msg_type in ("image", "sticker"):
            media_type = "image"
        elif msg_type == "video":
            media_type = "video"
        elif msg_type in ("audio", "voice"):
            media_type = "audio"
        elif msg_type == "document":
    # Treat image documents as images (preserves quality)
            mime = msg.get("document", {}).get("mime_type", "")
            if mime in ("image/jpeg", "image/png", "image/webp", "image/gif"):
                media_type = "image"

        try:
            t0 = time.time()
            reply = await handle_message(
                phone=phone,
                text=text,
                media_type=media_type,
                media_id=media_id,
                message_id=message_id,
            )
            elapsed = (time.time() - t0) * 1000
            logger.info("✅ [%s] %.0fms", phone, elapsed)

            if reply:
                await _send_reply(phone, reply)

        except Exception as e:
            logger.error("❌ handle_message [%s]: %s", phone, e, exc_info=True)
            try:
                await send_text(phone, "⚠️ An unexpected error occurred. Please try again.")
            except Exception:
                pass

    return JSONResponse({"status": "ok"}, status_code=200)

async def _send_reply(to: str, reply: str) -> None:
    """
    Handles special reply markers:
      BUTTONS:{entity}||1:{desc}...  → interactive button message
      text with __SCREENSHOT__{url}__SCREENSHOT__  → text + image
      text with __SECOND_MSG__{msg}__SECOND_MSG__  → separate second message
    """
    import re as _re

    if not reply:
        return

    # Extract screenshot URL if present
    screenshot_url = None
    scr_match = _re.search(r"__SCREENSHOT__(.+?)__SCREENSHOT__", reply)
    if scr_match:
        screenshot_url = scr_match.group(1).strip()
        reply = reply.replace(scr_match.group(0), "").strip()
        logger.info("📸 Screenshot marker found: %s", screenshot_url[:80])

    # Extract second message (e.g. profile offer or deepfake offer)
    second_msg = None
    sec_match = _re.search(r"__SECOND_MSG__(.+?)__SECOND_MSG__", reply, _re.DOTALL)
    if sec_match:
        second_msg = sec_match.group(1).strip()
        reply = reply.replace(sec_match.group(0), "").strip()
        logger.info("📨 Second message marker found: %s", second_msg[:80])

    # Button message
    if reply.startswith("BUTTONS:"):
        parts = reply.split("||")
        entity = parts[0][len("BUTTONS:"):]
        buttons = []
        for part in parts[1:]:
            if ":" in part:
                btn_id, btn_desc = part.split(":", 1)
                buttons.append({"id": btn_id.strip(), "title": btn_desc.strip()[:24]})
        body = f"🔍 `{entity}` — what would you like to do?"
        await send_buttons(to, body=body, buttons=buttons, footer="Tap to select")
    else:
        # Send main text reply
        await send_text(to, reply)

    # Send second message if present (e.g., profile/deepfake offer)
    if second_msg:
        try:
            await send_text(to, second_msg)
            logger.info("✅ Second message sent")
        except Exception as e:
            logger.warning("Second message send failed: %s", e)

    # Download and send screenshot if URL is present
    
    if screenshot_url:
        try:
            import httpx as _httpx
            logger.info("📸 Downloading screenshot: %s", screenshot_url[:80])
            async with _httpx.AsyncClient(timeout=_httpx.Timeout(20.0)) as _sc:
                sc_resp = await _sc.get(screenshot_url, follow_redirects=True)
                if sc_resp.status_code == 200 and sc_resp.content:
                    from app.whatsapp.client import send_image_bytes
                    success = await send_image_bytes(to, sc_resp.content,
                                           caption="Website Screenshot")
                    if success:
                        logger.info("✅ Screenshot sent successfully")
                    else:
                        logger.warning("Failed to send screenshot after download")
                else:
                    logger.warning("Screenshot download failed: HTTP %s", sc_resp.status_code)
        except Exception as e:
            logger.warning("Screenshot send failed: %s", e)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    redis_ok  = False
    ollama_ok = False
    try:
        r = await get_redis()
        await r.ping()
        redis_ok = True
    except Exception:
        pass
    ollama_ok = await is_ollama_available()
    return {
        "status": "healthy",
        "service": "aegis-orchestra",
        "redis": "connected" if redis_ok else "disconnected",
        "ollama": {"available": ollama_ok, "model": settings.ollama_model},
        "webhook": f"{settings.public_url}/webhook",
        "modules": {
            "link":       settings.link_analyzer_url,
            "qr":         settings.qr_scanner_url,
            "credential": settings.credential_analyzer_url,
            "profile":    settings.profile_analyzer_url,
        },
    }


@app.get("/")
async def root():
    return {
        "service": "Aegis AI — WhatsApp Orchestra",
        "webhook_url": f"{settings.public_url}/webhook",
        "verify_token": settings.whatsapp_verify_token,
        "docs": "/docs",
    }


# ── Test endpoint ─────────────────────────────────────────────────────────────

from pydantic import BaseModel as _BM
import os as _os

class _TReq(_BM):
    phone: str = "923009999999"
    text: str = ""
    media_type: str | None = None

class _TResp(_BM):
    reply: str
    phone: str
    elapsed_ms: float
    is_buttons: bool = False
    buttons: list = []

@app.get("/test/diagnose")
async def test_diagnose():
    """
    Tests connectivity to all 4 modules from inside the server process.
    Use this to diagnose Docker networking issues.
    """
    from app.router.health_check import check_all_modules
    results = await check_all_modules()
    return {
        "module_connectivity": results,
        "note": "If modules show False but health check on host passes, it is a Docker networking issue.",
        "fix": "Run fix_docker_network.ps1 (Windows) or fix_docker_network.sh (Linux), or run orchestra on host.",
    }


@app.post("/test/message", response_model=_TResp)
async def test_message(req: _TReq):
    if not (_os.getenv("TESTING","").lower()=="true" or settings.log_level.upper()=="DEBUG"):
        raise HTTPException(status_code=403, detail="Set TESTING=true in .env")
    t0 = time.time()
    try:
        reply = await handle_message(
            phone=req.phone, text=req.text,
            media_type=req.media_type, media_id=None, message_id="test-id",
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        reply = f"❌ Error: {e}"
    elapsed = (time.time() - t0) * 1000
    return _TResp(reply=reply, phone=req.phone, elapsed_ms=elapsed, is_buttons=False, buttons=[])

    """Integration test endpoint — requires TESTING=true in .env"""
    if not (_os.getenv("TESTING","").lower()=="true" or settings.log_level.upper()=="DEBUG"):
        raise HTTPException(status_code=403, detail="Set TESTING=true in .env")
    t0 = time.time()
    # Special diagnose command
    if req.text.strip() == "/diagnose":
        from app.router.health_check import check_all_modules
        mod_results = await check_all_modules()
        lines = ["🔍 *Module Connectivity (from inside server):*", ""]
        for name, ok in mod_results.items():
            lines.append(f"{'✅' if ok else '❌'} {name}")
        if not all(mod_results.values()):
            lines += ["", "⚠️ Some modules unreachable from Docker.",
                      "Run: fix_docker_network.ps1 (Win) or fix_docker_network.sh (Linux)",
                      "Or run orchestra on host: uvicorn app.main:app --port 8006"]
        reply = "\n".join(lines)
        elapsed = (time.time() - t0) * 1000
        return _TResp(reply=reply, phone=req.phone, elapsed_ms=elapsed)

    reply = await handle_message(
        phone=req.phone, text=req.text,
        media_type=req.media_type, media_id=None, message_id="test-id",
    )
    elapsed = (time.time() - t0) * 1000
    is_buttons = (reply or "").startswith("BUTTONS:")
    btns = []
    if is_buttons:
        parts = reply.split("||")
        for p in parts[1:]:
            if ":" in p:
                bid, bdesc = p.split(":", 1)
                btns.append({"id": bid.strip(), "title": bdesc.strip()})
    return _TResp(reply=reply or "", phone=req.phone, elapsed_ms=elapsed,
                  is_buttons=is_buttons, buttons=btns)
