"""tests/test_unit_security.py — Unit tests for security functions."""
import time
import pytest
from app.core.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token,
    create_email_token, decode_email_token,
    create_password_reset_token, decode_password_reset_token,
    hash_token,
)


# ── Password hashing ──────────────────────────────────────────────────────────

class TestPasswordHashing:

    def test_hash_returns_string(self):
        h = hash_password("MyPass1")
        assert isinstance(h, str)
        assert len(h) > 20

    def test_verify_correct_password(self):
        h = hash_password("MyPass1")
        assert verify_password("MyPass1", h) is True

    def test_reject_wrong_password(self):
        h = hash_password("MyPass1")
        assert verify_password("WrongPass1", h) is False

    def test_same_password_different_hashes(self):
        """bcrypt uses random salt — same input produces different hashes."""
        h1 = hash_password("MyPass1")
        h2 = hash_password("MyPass1")
        assert h1 != h2
        # But both should verify
        assert verify_password("MyPass1", h1)
        assert verify_password("MyPass1", h2)

    def test_short_password(self):
        h = hash_password("Ab1")
        assert verify_password("Ab1", h)

    def test_very_long_password_no_truncation(self):
        """bcrypt's 72-byte limit is bypassed by SHA-256 pre-hashing."""
        long_pass = "A" * 100 + "b1"          # 102 chars > 72 bytes
        h = hash_password(long_pass)
        assert verify_password(long_pass, h)
        # A different long password must NOT verify
        other_long = "A" * 99 + "Xb1"
        assert not verify_password(other_long, h)

    def test_unicode_password(self):
        pwd = "مرحبا123A"  # Arabic + numbers + uppercase
        h = hash_password(pwd)
        assert verify_password(pwd, h)
        assert not verify_password("مرحبا123B", h)

    def test_special_chars_password(self):
        pwd = "P@$$w0rd!#%^&*()"
        h = hash_password(pwd)
        assert verify_password(pwd, h)

    def test_empty_string_not_equal_to_anything(self):
        h = hash_password("SomePass1")
        assert not verify_password("", h)


# ── JWT tokens ────────────────────────────────────────────────────────────────

class TestJWT:

    def test_access_token_decode(self):
        token = create_access_token("user-123")
        payload = decode_token(token)
        assert payload is not None
        assert payload["sub"] == "user-123"
        assert payload["type"] == "access"

    def test_refresh_token_decode(self):
        token = create_refresh_token("user-456")
        payload = decode_token(token)
        assert payload is not None
        assert payload["sub"] == "user-456"
        assert payload["type"] == "refresh"

    def test_access_token_type_not_refresh(self):
        """Access token must not be usable as refresh token."""
        access = create_access_token("user-123")
        payload = decode_token(access)
        assert payload["type"] == "access"
        assert payload["type"] != "refresh"

    def test_invalid_token_returns_none(self):
        assert decode_token("not.a.real.token") is None
        assert decode_token("") is None
        assert decode_token("eyJ.invalid.signature") is None

    def test_tampered_token_rejected(self):
        token = create_access_token("user-123")
        # Modify last character
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        assert decode_token(tampered) is None

    def test_token_expiry_field_present(self):
        token = create_access_token("user-123")
        payload = decode_token(token)
        assert "exp" in payload
        assert payload["exp"] > time.time()


# ── Email verification token ──────────────────────────────────────────────────

class TestEmailToken:

    def test_email_token_encode_decode(self):
        token = create_email_token("uid-999", "user@example.com")
        payload = decode_email_token(token)
        assert payload is not None
        assert payload["sub"] == "uid-999"
        assert payload["email"] == "user@example.com"
        assert payload["type"] == "email_verify"

    def test_wrong_type_rejected(self):
        """Access token must NOT decode as email token."""
        access = create_access_token("uid-999")
        assert decode_email_token(access) is None

    def test_invalid_email_token(self):
        assert decode_email_token("garbage") is None


# ── Password reset token ──────────────────────────────────────────────────────

class TestPasswordResetToken:

    def test_reset_token_encode_decode(self):
        token = create_password_reset_token("uid-888")
        user_id = decode_password_reset_token(token)
        assert user_id == "uid-888"

    def test_wrong_type_not_a_reset_token(self):
        access = create_access_token("uid-888")
        assert decode_password_reset_token(access) is None

    def test_invalid_reset_token(self):
        assert decode_password_reset_token("not-a-token") is None


# ── Token hashing ─────────────────────────────────────────────────────────────

class TestHashToken:

    def test_hash_is_deterministic(self):
        t = "some-refresh-token-value"
        assert hash_token(t) == hash_token(t)

    def test_different_tokens_different_hashes(self):
        assert hash_token("tokenA") != hash_token("tokenB")

    def test_hash_is_64_chars(self):
        h = hash_token("any-token")
        assert len(h) == 64  # SHA-256 hex = 64 chars
