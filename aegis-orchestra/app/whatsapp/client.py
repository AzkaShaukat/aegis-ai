"""app/whatsapp/client.py — Meta WhatsApp Cloud API client.

Key features:
  - Message deduplication (prevents triple-send from duplicate webhooks)
  - Interactive button replies (1-click selection instead of typing 1/2/3)
  - Text messages with auto-split at 4096 chars
  - Media download
  - Webhook verification & signature check
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import time
from typing import Optional

import httpx

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

_WA_API_BASE = "https://graph.facebook.com/v19.0"

# ── In-memory deduplication (message_id → timestamp) ─────────────────────────
# Prevents processing the same message twice when Meta sends duplicate webhooks
_PROCESSED_IDS: dict[str, float] = {}
_DEDUP_WINDOW = 60  # seconds

async def send_image_bytes(to: str, image_bytes: bytes, caption: str = "") -> bool:
    """Send an image from bytes (upload to WhatsApp first)."""
    try:
        # Create a client without default JSON Content-Type
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Prepare multipart form data
            files = {
                'file': ('image.jpg', image_bytes, 'image/jpeg'),
            }
            data = {
                'messaging_product': 'whatsapp',
            }
            upload_url = f"{_WA_API_BASE}/{settings.whatsapp_phone_number_id}/media"
            # Add authorization header manually
            headers = {
                'Authorization': f'Bearer {settings.whatsapp_token}',
            }
            r = await client.post(upload_url, data=data, files=files, headers=headers)
            if r.status_code != 200:
                logger.error(f"Image upload failed: {r.status_code} {r.text}")
                return False
            media_id = r.json().get("id")
            if not media_id:
                logger.error("No media ID in upload response")
                return False
            # Send the image using the media ID (reuse existing _send_message which uses _get_client)
            return await _send_message(to, {
                "type": "image",
                "image": {"id": media_id, "caption": caption}
            })
    except Exception as e:
        logger.error(f"send_image_bytes error: {e}")
        return False
    
        

def _is_duplicate(message_id: str) -> bool:
    now = time.time()
    # Cleanup old entries
    expired = [k for k, v in _PROCESSED_IDS.items() if now - v > _DEDUP_WINDOW]
    for k in expired:
        del _PROCESSED_IDS[k]
    if message_id in _PROCESSED_IDS:
        return True
    _PROCESSED_IDS[message_id] = now
    return False


# ── Text message ──────────────────────────────────────────────────────────────

async def send_text(to: str, text: str, preview_url: bool = False) -> bool:
    """Send plain text. Auto-splits only when truly over 4000 chars."""
    if not text:
        return True
    # Only split if genuinely too long — avoid sending multiple messages for normal replies
    if len(text) <= 4000:
        return await _send_message(to, {
            "type": "text",
            "text": {"body": text, "preview_url": preview_url},
        })
    # Long reply — split at paragraph boundaries
    chunks = _split_message(text, 3900)
    for chunk in chunks:
        ok = await _send_message(to, {
            "type": "text",
            "text": {"body": chunk, "preview_url": preview_url},
        })
        if not ok:
            return False
    return True


# ── Interactive button message (1-click options) ──────────────────────────────

async def send_buttons(
    to: str,
    body: str,
    buttons: list[dict],  # [{"id": "1", "title": "Scan as URL"}, ...]
    header: str = "",
    footer: str = "Reply or tap a button",
) -> bool:
    """
    Send interactive button message — user taps instead of typing 1/2/3.
    Maximum 3 buttons per WhatsApp rules.
    Falls back to plain text if > 3 buttons.
    """
    if len(buttons) > 3:
        # Fallback to text for > 3 options
        text = body + "\n\n"
        emojis = ["1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣"]
        for i, btn in enumerate(buttons):
            text += f"{emojis[i]} {btn['title']}\n"
        text += "\nReply with a number."
        return await send_text(to, text)

    wa_buttons = [
        {"type": "reply", "reply": {"id": btn["id"], "title": btn["title"][:20]}}
        for btn in buttons
    ]

    interactive_obj: dict = {
        "type": "button",
        "body": {"text": body},
        "action": {"buttons": wa_buttons},
    }
    if header:
        interactive_obj["header"] = {"type": "text", "text": header[:60]}
    if footer:
        interactive_obj["footer"] = {"text": footer[:60]}

    ok = await _send_message(to, {
        "type": "interactive",
        "interactive": interactive_obj,
    })
    if ok:
        return True
    # Fallback: send as plain text with numbered options if interactive fails
    emojis = ["1️⃣", "2️⃣", "3️⃣"]
    text_fallback = body + "\n\n"
    for i, btn in enumerate(buttons):
        em = emojis[i] if i < len(emojis) else f"{i+1}."
        text_fallback += f"{em} {btn['title']}\n"
    text_fallback += "\nReply with a number."
    return await send_text(to, text_fallback)


# ── Image message ─────────────────────────────────────────────────────────────

async def send_image_url(to: str, image_url: str, caption: str = "") -> bool:
    return await _send_message(to, {
        "type": "image",
        "image": {"link": image_url, "caption": caption},
    })


# ── Media download ────────────────────────────────────────────────────────────

async def download_media(media_id: str) -> bytes:
    async with _get_client() as client:
        r1 = await client.get(f"{_WA_API_BASE}/{media_id}")
        r1.raise_for_status()
        download_url = r1.json()["url"]
        r2 = await client.get(download_url)
        r2.raise_for_status()
        return r2.content


# ── Read receipt ──────────────────────────────────────────────────────────────

async def mark_read(message_id: str) -> None:
    try:
        async with _get_client() as client:
            await client.post(
                f"{_WA_API_BASE}/{settings.whatsapp_phone_number_id}/messages",
                json={
                    "messaging_product": "whatsapp",
                    "status": "read",
                    "message_id": message_id,
                },
            )
    except Exception:
        pass


# ── Webhook helpers ───────────────────────────────────────────────────────────

def verify_webhook(mode: str, token: str, challenge: str) -> Optional[str]:
    if mode == "subscribe" and token == settings.whatsapp_verify_token:
        return challenge
    return None


def verify_signature(payload: bytes, signature_header: str) -> bool:
    if not settings.whatsapp_app_secret:
        return True
    if not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        settings.whatsapp_app_secret.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def parse_incoming(body: dict) -> list[dict]:
    """
    Parse raw webhook payload.
    Returns only actual user messages — filters out:
      - Status updates (delivered, read receipts)
      - System messages
      - Duplicate message IDs
    """
    messages = []
    try:
        for entry in body.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})

                # Skip pure status updates (no messages key)
                if "messages" not in value:
                    continue

                for msg in value.get("messages", []):
                    msg_id = msg.get("id", "")

                    # Deduplication — skip if already processed
                    if msg_id and _is_duplicate(msg_id):
                        logger.debug("Duplicate message skipped: %s", msg_id)
                        continue

                    parsed = {
                        "from_number": msg.get("from", ""),
                        "message_id":  msg_id,
                        "timestamp":   msg.get("timestamp", ""),
                        "type":        msg.get("type", "text"),
                        "text":        "",
                        "media_id":    "",
                        "media_mime":  "",
                    }
                    msg_type = msg.get("type", "text")

                    if msg_type == "text":
                        parsed["text"] = msg.get("text", {}).get("body", "")

                    elif msg_type in ("image", "video", "audio", "document", "sticker"):
                        media_obj = msg.get(msg_type, {})
                        parsed["media_id"]   = media_obj.get("id", "")
                        parsed["media_mime"] = media_obj.get("mime_type", "")
                        parsed["text"]       = media_obj.get("caption", "")

                    elif msg_type == "interactive":
                        # User tapped a button reply
                        reply = msg.get("interactive", {}).get("button_reply", {})
                        parsed["text"] = reply.get("id", reply.get("title", ""))
                        parsed["type"] = "text"

                    # Only include if we have a sender
                    if parsed["from_number"]:
                        messages.append(parsed)

    except Exception as e:
        logger.error("parse_incoming error: %s", e)
    return messages


# ── Internal ──────────────────────────────────────────────────────────────────

def _get_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={
            "Authorization": f"Bearer {settings.whatsapp_token}",
            "Content-Type": "application/json",
        },
        timeout=30.0,
    )


async def _send_message(to: str, message_obj: dict) -> bool:
    try:
        async with _get_client() as client:
            r = await client.post(
                f"{_WA_API_BASE}/{settings.whatsapp_phone_number_id}/messages",
                json={
                    "messaging_product": "whatsapp",
                    "recipient_type": "individual",
                    "to": to,
                    **message_obj,
                },
            )
            if r.status_code not in (200, 201):
                logger.error("WA send failed %d: %s", r.status_code, r.text[:200])
                return False
            return True
    except Exception as e:
        logger.error("WA send exception: %s", e)
        return False


def _split_message(text: str, max_len: int = 3900) -> list[str]:
    if len(text) <= max_len:
        return [text]
    chunks = []
    while text:
        if len(text) <= max_len:
            chunks.append(text)
            break
        split_at = text.rfind("\n\n", 0, max_len)
        if split_at == -1:
            split_at = text.rfind("\n", 0, max_len)
        if split_at == -1:
            split_at = max_len
        chunks.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    return chunks
