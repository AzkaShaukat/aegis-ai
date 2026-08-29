"""
chat_service_ext.py
Primary session management + message history + pruning.
One session per user. Messages auto-pruned after 30 days / 10k cap.
"""
from __future__ import annotations
import uuid, logging
from datetime import datetime, timezone, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

PRIMARY_TITLE  = "__aegis_primary__"
MAX_MESSAGES   = 10_000
PRUNE_DAYS     = 30
PRUNE_BATCH    = 200   # how many to delete when over limit


async def get_primary_session(db: AsyncSession, user_id: uuid.UUID) -> str:
    """Return session_id of the one persistent session for this user.
    Creates it on first call.
    """
    r = await db.execute(text("""
        SELECT id FROM chat_sessions
        WHERE user_id = :uid AND title = :title AND is_archived = false
        LIMIT 1
    """), {"uid": str(user_id), "title": PRIMARY_TITLE})
    row = r.fetchone()
    if row:
        return str(row[0])

    # Create it
    new_id = str(uuid.uuid4())
    now    = datetime.now(timezone.utc)
    await db.execute(text("""
        INSERT INTO chat_sessions (id, user_id, title, created_at, updated_at, is_archived)
        VALUES (:id, :uid, :title, :now, :now, false)
    """), {"id": new_id, "uid": str(user_id), "title": PRIMARY_TITLE, "now": now})
    await db.commit()
    logger.info("Created primary session %s for user %s", new_id[:8], str(user_id)[:8])
    return new_id

# backend/app/services/chat_service_ext.py

# backend/app/services/chat_service_ext.py

async def delete_session_messages(db: AsyncSession, session_id: str) -> int:
    """Delete all messages from a session. Returns count deleted."""
    result = await db.execute(
        text("DELETE FROM messages WHERE session_id = :sid RETURNING id"),
        {"sid": session_id}
    )
    deleted = len(result.fetchall())
    await db.commit()
    return deleted


async def prune_messages(db: AsyncSession, session_id: str):
    """Delete messages older than PRUNE_DAYS. If still over MAX_MESSAGES, delete oldest batch."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=PRUNE_DAYS)

    # Delete old messages
    r = await db.execute(text("""
        DELETE FROM messages
        WHERE session_id = :sid AND created_at < :cutoff
    """), {"sid": session_id, "cutoff": cutoff})
    deleted_old = r.rowcount
    if deleted_old:
        logger.info("Pruned %d messages older than %d days", deleted_old, PRUNE_DAYS)

    # If still over cap, delete oldest batch
    r2 = await db.execute(text(
        "SELECT COUNT(*) FROM messages WHERE session_id = :sid"),
        {"sid": session_id})
    count = r2.scalar() or 0
    if count > MAX_MESSAGES:
        over = count - MAX_MESSAGES + PRUNE_BATCH
        await db.execute(text("""
            DELETE FROM messages WHERE id IN (
                SELECT id FROM messages WHERE session_id = :sid
                ORDER BY created_at ASC LIMIT :over
            )
        """), {"sid": session_id, "over": over})
        logger.info("Pruned %d excess messages (was %d)", over, count)

    await db.commit()


async def get_history(
    db: AsyncSession, session_id: str,
    limit: int = 100, before_id: str | None = None
) -> list[dict]:
    """Paginated message history, newest-first for cursor, returned oldest-first."""
    if before_id:
        r = await db.execute(text("""
            SELECT id, role, content, structured, module_used, risk_level, created_at
            FROM messages
            WHERE session_id = :sid
              AND created_at < (SELECT created_at FROM messages WHERE id = :bid)
            ORDER BY created_at DESC LIMIT :lim
        """), {"sid": session_id, "bid": before_id, "lim": limit})
    else:
        r = await db.execute(text("""
            SELECT id, role, content, structured, module_used, risk_level, created_at
            FROM messages
            WHERE session_id = :sid
            ORDER BY created_at DESC LIMIT :lim
        """), {"sid": session_id, "lim": limit})

    rows = r.fetchall()
    rows = list(reversed(rows))   # return oldest-first
    return [{
        "id":         str(row[0]),
        "role":       str(row[1]),
        "content":    row[2] or "",
        "structured": row[3],
        "module_used": row[4],
        "risk_level":  row[5],
        "created_at":  row[6].isoformat() if row[6] else None,
    } for row in rows]


async def get_scan_stats_raw(db: AsyncSession, user_id: uuid.UUID) -> dict:
    """Quick stats for sidebar."""
    r = await db.execute(text("""
        SELECT m.module_used, m.risk_level, m.content, m.created_at
        FROM messages m
        JOIN chat_sessions cs ON cs.id = m.session_id
        WHERE cs.user_id = :uid AND m.role = 'bot'
          AND m.module_used IS NOT NULL
          AND m.module_used NOT IN ('help','system','cyber_qa')
        ORDER BY m.created_at DESC LIMIT 200
    """), {"uid": str(user_id)})
    rows = r.fetchall()
    total = len(rows)
    safe    = sum(1 for r in rows if str(r[1] or "").upper() in ("SAFE","LOW","CLEAN"))
    danger  = sum(1 for r in rows if str(r[1] or "").upper() in ("HIGH","CRITICAL","FAKE","DEEPFAKE"))
    warning = total - safe - danger

    recent = [{
        "module":  r[0],
        "risk":    r[1] or "UNKNOWN",
        "excerpt": (r[2] or "")[:60],
        "time":    r[3].isoformat() if r[3] else None,
    } for r in rows[:10]]

    return {"total": total, "safe": safe, "warning": warning,
            "danger": danger, "recent": recent}
