"""alembic/env.py — Standalone sync migrations. Imports nothing from app/."""
from __future__ import annotations
import os, re
from logging.config import fileConfig
from sqlalchemy import (
    engine_from_config, pool, text,
    Column, String, Boolean, DateTime, Text, ForeignKey,
    Enum as SAEnum, MetaData, Table,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from alembic import context

config = context.config
if config.config_file_name:
    fileConfig(config.config_file_name)

_meta = MetaData()
Table("users", _meta,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("email", String(255), unique=True, nullable=False),
    Column("password_hash", String(512), nullable=False),
    Column("display_name", String(100), nullable=False),
    Column("is_active", Boolean(), nullable=False, server_default="true"),
    Column("email_verified", Boolean(), nullable=False, server_default="false"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
    Column("last_login", DateTime(timezone=True), nullable=True),
)
Table("chat_sessions", _meta,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")),
    Column("title", String(255), nullable=False, server_default="New Chat"),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
    Column("is_archived", Boolean(), nullable=False, server_default="false"),
)
Table("messages", _meta,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("session_id", UUID(as_uuid=True), ForeignKey("chat_sessions.id", ondelete="CASCADE")),
    Column("role", SAEnum("user", "bot", name="messagerole"), nullable=False),
    Column("content", Text(), nullable=False),
    Column("structured", JSONB(), nullable=True),
    Column("media_url", String(500), nullable=True),
    Column("media_type", String(50), nullable=True),
    Column("module_used", String(50), nullable=True),
    Column("risk_level", String(50), nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
)
Table("refresh_tokens", _meta,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")),
    Column("token_hash", String(64), nullable=False, unique=True),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
    Column("is_revoked", Boolean(), nullable=False, server_default="false"),
)
Table("scan_history", _meta,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")),
    Column("value_hash", String(16), nullable=False),
    Column("entry_type", String(50), nullable=False),
    Column("verdict", String(50), nullable=False),
    Column("risk_level", String(50), nullable=False),
    Column("scanned_at", DateTime(timezone=True), nullable=False, server_default=text("now()")),
    Column("expires_at", DateTime(timezone=True), nullable=False),
)
target_metadata = _meta

def _url():
    u = os.environ.get("DATABASE_URL") or config.get_main_option("sqlalchemy.url","")
    return re.sub(r"postgresql\+asyncpg://", "postgresql+psycopg2://", u)

def run_migrations_offline():
    context.configure(url=_url(), target_metadata=target_metadata,
                      literal_binds=True, dialect_opts={"paramstyle":"named"})
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = _url()
    e = engine_from_config(cfg, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with e.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()