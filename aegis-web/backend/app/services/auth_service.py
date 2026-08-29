"""app/services/auth_service.py — User CRUD, auth, email verification, password reset."""
from __future__ import annotations
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import get_settings
from app.core.security import (
    create_access_token, create_refresh_token, create_email_token,
    create_password_reset_token, decode_email_token, decode_password_reset_token,
    hash_password, hash_token, verify_password,
)
from app.models.chat import RefreshToken
from app.models.user import User

settings = get_settings()


class AuthError(Exception):
    """Raised for auth failures — message shown directly to frontend."""
    pass


# ── Register ──────────────────────────────────────────────────────────────────

async def create_user(db: AsyncSession, email: str, password: str, display_name: str) -> User:
    result = await db.execute(select(User).where(User.email == email.lower()))
    if result.scalar_one_or_none():
        raise AuthError("An account with this email already exists. Try signing in instead.")

    # Auto-verify when email is disabled — user can log in immediately
    auto_verify = not settings.email_enabled

    user = User(
        email=email.lower(),
        password_hash=hash_password(password),
        display_name=display_name,
        email_verified=auto_verify,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


async def send_verification_for(user: User) -> bool:
    """Send verification email. Returns True on success, False if email not configured."""
    if not settings.email_enabled or not settings.smtp_user:
        return False
    try:
        from app.services.email_service import send_verification_email
        token = create_email_token(str(user.id), user.email)
        url   = f"{settings.frontend_url}/verify-email?token={token}"
        return await send_verification_email(user.email, user.display_name, url)
    except Exception:
        return False


# ── Email verification ─────────────────────────────────────────────────────────

async def verify_email(db: AsyncSession, token: str) -> User:
    payload = decode_email_token(token)
    if not payload:
        raise AuthError("This verification link is invalid or has expired. Please request a new one.")
    user_id = uuid.UUID(payload["sub"])
    result  = await db.execute(select(User).where(User.id == user_id))
    user    = result.scalar_one_or_none()
    if not user:
        raise AuthError("Account not found.")
    if user.email_verified:
        return user  # already verified — idempotent
    if payload.get("email") != user.email:
        raise AuthError("This verification link is no longer valid.")
    user.email_verified = True
    await db.flush()
    return user


# ── Login ──────────────────────────────────────────────────────────────────────

async def authenticate_user(db: AsyncSession, email: str, password: str) -> User:
    result = await db.execute(select(User).where(User.email == email.lower()))
    user   = result.scalar_one_or_none()

    if not user:
        raise AuthError(
            "No account found with this email address. "
            "Please check your email or create a new account."
        )
    if not user.is_active:
        raise AuthError("This account has been deactivated. Please contact support.")
    if not verify_password(password, user.password_hash):
        raise AuthError(
            "Incorrect password. Please try again, "
            "or use 'Forgot password?' to reset it."
        )
    # Only enforce email verification when email is actually enabled AND working
    if settings.email_enabled and settings.smtp_user and not user.email_verified:
        raise AuthError(
            "Your email address has not been verified yet. "
            "Please check your inbox for the verification link, "
            "or click 'Resend' below."
        )

    await db.execute(
        update(User).where(User.id == user.id)
        .values(last_login=datetime.now(timezone.utc))
    )
    return user


# ── Token issuance ─────────────────────────────────────────────────────────────

async def issue_tokens(db: AsyncSession, user: User) -> dict:
    """
    Issue a fresh access + refresh token pair.

    Generates up to 3 unique refresh tokens to handle the (very unlikely)
    case of a hash collision without ever rolling back the caller's session.
    Rolling back here would corrupt the caller's transaction, causing the
    MissingGreenlet error seen in logs.
    """
    user_id_str = str(user.id)
    access = create_access_token(user_id_str)

    # Try up to 3 times to get a non-colliding refresh token hash
    for attempt in range(3):
        refresh    = create_refresh_token(user_id_str)
        token_hash = hash_token(refresh)
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)

        # Check if this hash already exists (avoids letting the DB raise)
        existing = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        if existing.scalar_one_or_none() is None:
            break  # unique — use it
        # Hash collision (extremely rare) — loop and try a new token
    else:
        raise RuntimeError("Could not generate a unique refresh token after 3 attempts")

    db.add(RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
    ))
    await db.flush()

    return {
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "bearer",
        "expires_in":    settings.access_token_expire_minutes * 60,
    }


async def refresh_access_token(db: AsyncSession, raw_refresh_token: str) -> Optional[dict]:
    from app.core.security import decode_token
    payload = decode_token(raw_refresh_token)
    if not payload or payload.get("type") != "refresh":
        return None
    token_hash = hash_token(raw_refresh_token)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.is_revoked == False,  # noqa: E712
        )
    )
    rt = result.scalar_one_or_none()
    if not rt or rt.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return None
    rt.is_revoked = True
    await db.flush()
    user_result = await db.execute(select(User).where(User.id == rt.user_id))
    user        = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        return None
    return await issue_tokens(db, user)


async def revoke_refresh_token(db: AsyncSession, raw_refresh_token: str) -> None:
    token_hash = hash_token(raw_refresh_token)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    rt = result.scalar_one_or_none()
    if rt:
        rt.is_revoked = True
        await db.flush()


# ── Password reset ─────────────────────────────────────────────────────────────

async def send_password_reset(db: AsyncSession, email: str) -> None:
    result = await db.execute(select(User).where(User.email == email.lower()))
    user   = result.scalar_one_or_none()
    if not user or not user.is_active:
        return  # silent — prevent account enumeration
    if not settings.smtp_user:
        return  # email not configured — silent
    try:
        from app.services.email_service import send_password_reset_email
        token = create_password_reset_token(str(user.id))
        url   = f"{settings.frontend_url}/reset-password?token={token}"
        await send_password_reset_email(user.email, user.display_name, url)
    except Exception:
        pass


async def reset_password(db: AsyncSession, token: str, new_password: str) -> User:
    user_id_str = decode_password_reset_token(token)
    if not user_id_str:
        raise AuthError("This reset link is invalid or has expired (links expire after 1 hour).")
    user_id = uuid.UUID(user_id_str)
    result  = await db.execute(select(User).where(User.id == user_id))
    user    = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise AuthError("Account not found.")
    user.password_hash = hash_password(new_password)
    await db.flush()
    return user


async def resend_verification(db: AsyncSession, email: str) -> None:
    result = await db.execute(select(User).where(User.email == email.lower()))
    user   = result.scalar_one_or_none()
    if not user or user.email_verified:
        return  # silent
    await send_verification_for(user)
