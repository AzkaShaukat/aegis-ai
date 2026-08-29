"""app/services/chat_service.py — PostgreSQL operations for chat sessions and messages."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.models.chat import ChatSession, Message, MessageRole
from app.models.scan_history import ScanHistory
from app.models.user import User

settings = get_settings()


# ── Session management ────────────────────────────────────────────────────────

async def get_or_create_session(
    db: AsyncSession,
    user_id: uuid.UUID,
    session_id: Optional[str],
) -> ChatSession:
    """
    If session_id is provided and belongs to the user → return it.
    Otherwise → create a new session.
    """
    if session_id:
        try:
            sid = uuid.UUID(session_id)
            result = await db.execute(
                select(ChatSession).where(
                    ChatSession.id == sid,
                    ChatSession.user_id == user_id,
                    ChatSession.is_archived == False,  # noqa: E712
                )
            )
            session = result.scalar_one_or_none()
            if session:
                return session
        except (ValueError, AttributeError):
            pass

    # Create new session
    session = ChatSession(user_id=user_id, title="New Chat")
    db.add(session)
    await db.flush()
    await db.refresh(session)
    return session


async def list_sessions(db: AsyncSession, user_id: uuid.UUID) -> list[dict]:
    """Return all non-archived sessions for a user with message count."""
    result = await db.execute(
        select(ChatSession)
        .where(
            ChatSession.user_id == user_id,
            ChatSession.is_archived == False,  # noqa: E712
        )
        .order_by(ChatSession.updated_at.desc())
    )
    sessions = result.scalars().all()

    out = []
    for s in sessions:
        count_result = await db.execute(
            select(func.count()).where(Message.session_id == s.id)
        )
        count = count_result.scalar() or 0
        out.append({
            "id": s.id,
            "title": s.title,
            "created_at": s.created_at,
            "updated_at": s.updated_at,
            "is_archived": s.is_archived,
            "message_count": count,
        })
    return out


async def get_session_with_messages(
    db: AsyncSession,
    session_id: uuid.UUID,
    user_id: uuid.UUID,
) -> Optional[ChatSession]:
    """Fetch a session and its messages (must belong to user)."""
    result = await db.execute(
        select(ChatSession)
        .where(ChatSession.id == session_id, ChatSession.user_id == user_id)
        .options(selectinload(ChatSession.messages))
    )
    return result.scalar_one_or_none()


async def rename_session(
    db: AsyncSession,
    session_id: uuid.UUID,
    user_id: uuid.UUID,
    title: str,
) -> Optional[ChatSession]:
    result = await db.execute(
        select(ChatSession).where(
            ChatSession.id == session_id, ChatSession.user_id == user_id
        )
    )
    session = result.scalar_one_or_none()
    if session:
        session.title = title[:255]
        await db.flush()
    return session


async def archive_session(
    db: AsyncSession,
    session_id: uuid.UUID,
    user_id: uuid.UUID,
) -> bool:
    result = await db.execute(
        select(ChatSession).where(
            ChatSession.id == session_id, ChatSession.user_id == user_id
        )
    )
    session = result.scalar_one_or_none()
    if session:
        session.is_archived = True
        await db.flush()
        return True
    return False


# ── Message persistence ───────────────────────────────────────────────────────



def _make_title(text: str) -> str:
    """Create a short session title from message text."""
    if not text or text in ("[image]", "[message]", "[file]"):
        return "Image / File analysis"
    # Strip URL scheme for cleaner titles
    t = text.strip()
    if t.startswith(("http://", "https://")):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(t)
            t = parsed.netloc + (parsed.path[:20] if parsed.path and parsed.path != "/" else "")
        except Exception:
            pass
    # Truncate to 45 chars
    return t[:45] + ("…" if len(t) > 45 else "")

async def save_message(
    db: AsyncSession,
    session: ChatSession,
    role: MessageRole,
    content: str,
    structured: Optional[dict] = None,
    module_used: Optional[str] = None,
    risk_level: Optional[str] = None,
    media_url: Optional[str] = None,
    media_type: Optional[str] = None,
) -> Message:
    """Persist one message and bump session.updated_at."""
    msg = Message(
        session_id=session.id,
        role=str(getattr(role,"value",role)).lower(),
        content=content,
        structured=structured,
        module_used=module_used,
        risk_level=risk_level,
        media_url=media_url,
        media_type=media_type,
    )
    db.add(msg)
    session.updated_at = datetime.now(timezone.utc)

    # Auto-title from first user message
    if role  and session.title == "New Chat":
        session.title = content[:60].strip() or "New Chat"

    await db.flush()
    await db.refresh(msg)
    return msg


# ── Scan history ──────────────────────────────────────────────────────────────

def _hash_value(value: str) -> str:
    """First 16 chars of SHA-256 — anonymised, not reversible."""
    return hashlib.sha256(value.lower().encode()).hexdigest()[:16]


async def log_scan(
    db: AsyncSession,
    user_id: uuid.UUID,
    entry_type: str,
    scanned_value: str,
    verdict: str,
    risk_level: str,
) -> None:
    """Append an entry to scan_history with a 30-day expiry."""
    now = datetime.now(timezone.utc)
    entry = ScanHistory(
        user_id=user_id,
        value_hash=_hash_value(scanned_value),
        entry_type=entry_type,
        verdict=verdict,
        risk_level=risk_level,
        scanned_at=now,
        expires_at=now + timedelta(days=settings.scan_history_days),
    )
    db.add(entry)
    await db.flush()


async def get_scan_history(
    db: AsyncSession,
    user_id: uuid.UUID,
    days: int = 30,
) -> list[ScanHistory]:
    """Return scan entries within the last N days (still unexpired)."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(ScanHistory)
        .where(
            ScanHistory.user_id == user_id,
            ScanHistory.scanned_at >= cutoff,
            ScanHistory.expires_at >= datetime.now(timezone.utc),
        )
        .order_by(ScanHistory.scanned_at.desc())
    )
    return result.scalars().all()


async def get_scan_stats(db: AsyncSession, user_id: uuid.UUID) -> dict:
    """Aggregated stats for the history dashboard."""
    history = await get_scan_history(db, user_id, days=30)
    threat_types = {"high", "critical"}
    return {
        "total_scans":          len(history),
        "threats_found":        sum(1 for h in history if h.risk_level.lower() in threat_types),
        "links_scanned":        sum(1 for h in history if h.entry_type == "link"),
        "credentials_checked":  sum(1 for h in history if h.entry_type == "credential"),
        "profiles_analysed":    sum(1 for h in history if h.entry_type == "profile"),
        "smishing_detected":    sum(1 for h in history if h.entry_type == "smishing" and h.verdict != "legitimate"),
    }
