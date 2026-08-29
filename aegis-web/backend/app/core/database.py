"""app/core/database.py — Async SQLAlchemy engine, session factory, Base."""
from __future__ import annotations
import logging
from sqlalchemy.ext.asyncio import (
    create_async_engine, AsyncSession, async_sessionmaker,
)
from sqlalchemy.orm import DeclarativeBase
from app.core.config import get_settings

settings = get_settings()
logger   = logging.getLogger(__name__)

engine = create_async_engine(
    settings.database_url,
    echo=(settings.environment == "development"),
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db():
    """FastAPI dependency — yields an async DB session with automatic commit/rollback."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Async fallback: create all tables directly via SQLAlchemy.
    Used when alembic subprocess is not available.
    NOTE: This does NOT run ALTER TABLE — only CREATE TABLE IF NOT EXISTS.
    """
    from app.models import user, chat, scan_history  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ init_db: all tables ensured via create_all")
