"""Initial schema: users, chat_sessions, messages, refresh_tokens, scan_history

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-04-12
"""
from __future__ import annotations
from typing import Sequence, Union
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── users ──────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id",             postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email",          sa.String(255), nullable=False),
        sa.Column("password_hash",  sa.String(255), nullable=False),
        sa.Column("display_name",   sa.String(100), nullable=False),
        sa.Column("is_active",      sa.Boolean(),   nullable=False, server_default="true"),
        sa.Column("email_verified", sa.Boolean(),   nullable=False, server_default="false"),
        sa.Column("created_at",     sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("last_login",     sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # ── chat_sessions ───────────────────────────────────────────────────────────
    op.create_table(
        "chat_sessions",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id",     postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title",       sa.String(255), nullable=False, server_default="New Chat"),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at",  sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("is_archived", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.create_index("ix_chat_sessions_user_id", "chat_sessions", ["user_id"])

    # ── messages ────────────────────────────────────────────────────────────────
    op.create_table(
        "messages",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id",  postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role",        sa.Enum("user", "bot", name="messagerole"), nullable=False),
        sa.Column("content",     sa.Text(), nullable=False),
        sa.Column("structured",  postgresql.JSONB(), nullable=True),
        sa.Column("media_url",   sa.String(500), nullable=True),
        sa.Column("media_type",  sa.String(50),  nullable=True),
        sa.Column("module_used", sa.String(50),  nullable=True),
        sa.Column("risk_level",  sa.String(50),  nullable=True),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_messages_session_id", "messages", ["session_id"])

    # ── refresh_tokens ──────────────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id",     postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash",  sa.String(64), nullable=False),
        sa.Column("expires_at",  sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at",  sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("is_revoked",  sa.Boolean(), nullable=False, server_default="false"),
    )
    op.create_index("ix_refresh_tokens_user_id",    "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_token_hash", "refresh_tokens", ["token_hash"], unique=True)

    # ── scan_history ────────────────────────────────────────────────────────────
    op.create_table(
        "scan_history",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id",     postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("value_hash",  sa.String(16),  nullable=False),
        sa.Column("entry_type",  sa.String(50),  nullable=False),
        sa.Column("verdict",     sa.String(50),  nullable=False),
        sa.Column("risk_level",  sa.String(50),  nullable=False),
        sa.Column("scanned_at",  sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("expires_at",  sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_history_user_id",    "scan_history", ["user_id"])
    op.create_index("ix_scan_history_scanned_at", "scan_history", ["scanned_at"])


def downgrade() -> None:
    op.drop_table("scan_history")
    op.drop_table("refresh_tokens")
    op.drop_table("messages")
    op.drop_table("chat_sessions")
    op.drop_table("users")
    op.execute("DROP TYPE IF EXISTS messagerole")
