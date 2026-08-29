"""002_email_verified - DEPRECATED: email_verified is now in 001_initial_schema.
   This migration is kept as a no-op to avoid breaking existing installs that
   already ran 001 without email_verified.

Revision ID: 002_email_verified
Revises: 001_initial_schema
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision      = "002_email_verified"
down_revision = "001_initial_schema"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    """Add email_verified if it doesn't already exist (safe to run multiple times)."""
    conn = op.get_bind()
    result = conn.execute(sa.text(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_name='users' AND column_name='email_verified'"
    ))
    if not result.fetchone():
        op.add_column(
            "users",
            sa.Column("email_verified", sa.Boolean(), nullable=False, server_default="false"),
        )


def downgrade() -> None:
    pass  # leave email_verified in place on downgrade
