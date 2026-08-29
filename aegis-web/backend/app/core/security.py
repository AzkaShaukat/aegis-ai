"""app/core/security.py — Auth security using ONLY Python stdlib.

Password hashing: hashlib.pbkdf2_hmac (built-in, no external library needed).
NO passlib, NO bcrypt dependency — eliminates the 72-byte error permanently.

Algorithm: PBKDF2-SHA256, 260000 iterations, 32-byte salt (matches Django standard).
Format: pbkdf2_sha256$260000$<b64_salt>$<b64_hash>
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

from app.core.config import get_settings

settings = get_settings()

# ── PBKDF2 password hashing (pure stdlib) ─────────────────────────────────────

_ALGO       = "sha256"
_ITERATIONS = 260_000
_SALT_LEN   = 16   # bytes → 22 base64 chars
_KEY_LEN    = 32   # bytes → 44 base64 chars


def hash_password(plain: str) -> str:
    """Hash a password with PBKDF2-SHA256. Works for ANY password length."""
    salt = os.urandom(_SALT_LEN)
    dk   = hashlib.pbkdf2_hmac(_ALGO, plain.encode("utf-8"), salt, _ITERATIONS, _KEY_LEN)
    b64_salt = base64.b64encode(salt).decode("ascii")
    b64_hash = base64.b64encode(dk).decode("ascii")
    return f"pbkdf2_sha256${_ITERATIONS}${b64_salt}${b64_hash}"


def verify_password(plain: str, stored: str) -> bool:
    """Verify a password against a stored PBKDF2 hash."""
    try:
        parts = stored.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2])
        expected = base64.b64decode(parts[3])
        dk = hashlib.pbkdf2_hmac(_ALGO, plain.encode("utf-8"), salt, iterations, _KEY_LEN)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ── JWT tokens ────────────────────────────────────────────────────────────────

def create_access_token(user_id: str) -> str:
    expire  = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": user_id, "exp": expire, "type": "access"}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: str) -> str:
    expire  = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    payload = {"sub": user_id, "exp": expire, "type": "refresh"}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None


def create_email_token(user_id: str, email: str) -> str:
    expire  = datetime.now(timezone.utc) + timedelta(hours=24)
    payload = {"sub": user_id, "email": email, "exp": expire, "type": "email_verify"}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_email_token(token: str) -> Optional[dict]:
    payload = decode_token(token)
    if payload and payload.get("type") == "email_verify":
        return payload
    return None


def create_password_reset_token(user_id: str) -> str:
    expire  = datetime.now(timezone.utc) + timedelta(hours=1)
    payload = {"sub": user_id, "exp": expire, "type": "pwd_reset"}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_password_reset_token(token: str) -> Optional[str]:
    payload = decode_token(token)
    if payload and payload.get("type") == "pwd_reset":
        return payload.get("sub")
    return None


def hash_token(token: str) -> str:
    """SHA-256 hash of a refresh token for DB storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_secure_token() -> str:
    return secrets.token_urlsafe(32)
