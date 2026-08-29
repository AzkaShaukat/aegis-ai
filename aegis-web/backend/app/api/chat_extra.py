"""chat_extra.py — extra REST endpoints for single-session history."""
import uuid
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.core.database     import get_db
from app.models.user        import User
from app.services.chat_service_ext import (
    get_primary_session, get_history, get_scan_stats_raw, prune_messages
)

router = APIRouter(prefix="/api/chat", tags=["chat-v2"])


@router.get("/primary-session")
async def primary_session(
    u: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return (or create) the user's single persistent session id."""
    sid = await get_primary_session(db, u.id)
    await prune_messages(db, sid)
    return {"session_id": sid}


@router.get("/history")
async def history(
    limit:     int           = Query(100, le=200),
    before_id: str | None    = Query(None),
    u: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    sid  = await get_primary_session(db, u.id)
    msgs = await get_history(db, sid, limit=limit, before_id=before_id)
    return {"session_id": sid, "messages": msgs, "count": len(msgs)}


@router.get("/sidebar-stats")
async def sidebar_stats(
    u: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await get_scan_stats_raw(db, u.id)
