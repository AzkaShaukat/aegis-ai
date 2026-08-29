"""tests/test_integration_auth.py — Integration tests for /api/auth/* endpoints."""
import pytest
import pytest_asyncio
from httpx import AsyncClient


# ── Register ──────────────────────────────────────────────────────────────────

class TestRegister:
    """POST /api/auth/register"""

    @pytest.mark.asyncio
    async def test_register_success(self, client: AsyncClient):
        r = await client.post("/api/auth/register", json={
            "email": "new@example.com",
            "password": "NewPass1",
            "display_name": "New User",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["email"] == "new@example.com"
        assert data["display_name"] == "New User"
        assert "id" in data
        assert "password" not in data          # never expose password
        assert "password_hash" not in data

    @pytest.mark.asyncio
    async def test_register_auto_verified_when_email_disabled(self, client: AsyncClient):
        """When EMAIL_ENABLED=false, users are auto-verified so they can log in immediately."""
        r = await client.post("/api/auth/register", json={
            "email": "autoverify@example.com",
            "password": "AutoVerify1",
            "display_name": "Auto",
        })
        assert r.status_code == 201
        # email_enabled=false in test env → should be verified immediately
        assert r.json()["email_verified"] is True

    @pytest.mark.asyncio
    async def test_register_duplicate_email_rejected(self, client: AsyncClient):
        payload = {"email": "dup@example.com", "password": "DupPass1", "display_name": "Dup"}
        await client.post("/api/auth/register", json=payload)
        r = await client.post("/api/auth/register", json=payload)
        assert r.status_code == 409
        assert "already exists" in r.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_register_invalid_email_rejected(self, client: AsyncClient):
        r = await client.post("/api/auth/register", json={
            "email": "not-an-email",
            "password": "GoodPass1",
            "display_name": "User",
        })
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_register_weak_password_rejected(self, client: AsyncClient):
        r = await client.post("/api/auth/register", json={
            "email": "weak@example.com",
            "password": "short",        # < 8 chars
            "display_name": "Weak",
        })
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_register_password_no_uppercase_rejected(self, client: AsyncClient):
        r = await client.post("/api/auth/register", json={
            "email": "noup@example.com",
            "password": "alllowercase1",   # no uppercase
            "display_name": "User",
        })
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_register_empty_display_name_rejected(self, client: AsyncClient):
        r = await client.post("/api/auth/register", json={
            "email": "empty@example.com",
            "password": "GoodPass1",
            "display_name": "",
        })
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_register_email_case_insensitive(self, client: AsyncClient):
        """Email is normalised to lowercase — UPPER@EXAMPLE.COM == upper@example.com."""
        await client.post("/api/auth/register", json={
            "email": "UPPER@EXAMPLE.COM", "password": "GoodPass1", "display_name": "Upper",
        })
        r = await client.post("/api/auth/register", json={
            "email": "upper@example.com", "password": "GoodPass1", "display_name": "Upper",
        })
        assert r.status_code == 409  # duplicate

    @pytest.mark.asyncio
    async def test_register_very_long_password_works(self, client: AsyncClient):
        """Passwords longer than 72 bytes must work (bcrypt 72-byte limit is bypassed)."""
        long_pwd = "A" * 100 + "b1"  # 102 chars
        r = await client.post("/api/auth/register", json={
            "email": "longpwd@example.com",
            "password": long_pwd,
            "display_name": "Long",
        })
        assert r.status_code == 201


# ── Login ─────────────────────────────────────────────────────────────────────

class TestLogin:
    """POST /api/auth/login"""

    @pytest.mark.asyncio
    async def test_login_success_returns_tokens(self, client: AsyncClient, registered_user: dict):
        r = await client.post("/api/auth/login", json={
            "email": "test@example.com", "password": "TestPass1",
        })
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 900  # 15 minutes

    @pytest.mark.asyncio
    async def test_login_wrong_email_gives_clear_message(self, client: AsyncClient):
        r = await client.post("/api/auth/login", json={
            "email": "nobody@example.com", "password": "AnyPass1",
        })
        assert r.status_code == 401
        assert "no account" in r.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_login_wrong_password_gives_clear_message(
        self, client: AsyncClient, registered_user: dict
    ):
        r = await client.post("/api/auth/login", json={
            "email": "test@example.com", "password": "WrongPass1",
        })
        assert r.status_code == 401
        assert "incorrect password" in r.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_login_case_insensitive_email(
        self, client: AsyncClient, registered_user: dict
    ):
        r = await client.post("/api/auth/login", json={
            "email": "TEST@EXAMPLE.COM", "password": "TestPass1",
        })
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_login_returns_different_tokens_each_time(
        self, client: AsyncClient, registered_user: dict
    ):
        r1 = await client.post("/api/auth/login", json={"email": "test@example.com", "password": "TestPass1"})
        r2 = await client.post("/api/auth/login", json={"email": "test@example.com", "password": "TestPass1"})
        assert r1.json()["access_token"] != r2.json()["access_token"]


# ── Me ────────────────────────────────────────────────────────────────────────

class TestMe:
    """GET /api/auth/me"""

    @pytest.mark.asyncio
    async def test_me_returns_user_profile(
        self, client: AsyncClient, registered_user: dict, auth_headers: dict
    ):
        r = await client.get("/api/auth/me", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == "test@example.com"
        assert data["display_name"] == "Test User"
        assert "password" not in data
        assert "password_hash" not in data

    @pytest.mark.asyncio
    async def test_me_without_token_rejected(self, client: AsyncClient):
        r = await client.get("/api/auth/me")
        assert r.status_code == 403  # HTTPBearer returns 403 on missing token

    @pytest.mark.asyncio
    async def test_me_with_invalid_token_rejected(self, client: AsyncClient):
        r = await client.get("/api/auth/me", headers={"Authorization": "Bearer fake.token.here"})
        assert r.status_code == 401


# ── Token Refresh ─────────────────────────────────────────────────────────────

class TestTokenRefresh:
    """POST /api/auth/refresh"""

    @pytest.mark.asyncio
    async def test_refresh_returns_new_access_token(
        self, client: AsyncClient, auth_tokens: dict
    ):
        r = await client.post("/api/auth/refresh", json={
            "refresh_token": auth_tokens["refresh_token"]
        })
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        # New access token should be different from original
        assert data["access_token"] != auth_tokens["access_token"]

    @pytest.mark.asyncio
    async def test_refresh_token_rotated_on_use(
        self, client: AsyncClient, auth_tokens: dict
    ):
        """After using a refresh token, it should be invalidated (rotation)."""
        await client.post("/api/auth/refresh", json={
            "refresh_token": auth_tokens["refresh_token"]
        })
        # Using the same refresh token again should fail
        r2 = await client.post("/api/auth/refresh", json={
            "refresh_token": auth_tokens["refresh_token"]
        })
        assert r2.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_refresh_token_rejected(self, client: AsyncClient):
        r = await client.post("/api/auth/refresh", json={
            "refresh_token": "not.a.real.token"
        })
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_new_access_token_works_for_me(
        self, client: AsyncClient, auth_tokens: dict
    ):
        """New access token from refresh should work for authenticated endpoints."""
        r = await client.post("/api/auth/refresh", json={
            "refresh_token": auth_tokens["refresh_token"]
        })
        new_token = r.json()["access_token"]
        me = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {new_token}"})
        assert me.status_code == 200


# ── Logout ────────────────────────────────────────────────────────────────────

class TestLogout:
    """POST /api/auth/logout"""

    @pytest.mark.asyncio
    async def test_logout_revokes_refresh_token(
        self, client: AsyncClient, auth_tokens: dict
    ):
        # Logout
        r = await client.post("/api/auth/logout", json={
            "refresh_token": auth_tokens["refresh_token"]
        })
        assert r.status_code == 204

        # Using revoked refresh token should fail
        r2 = await client.post("/api/auth/refresh", json={
            "refresh_token": auth_tokens["refresh_token"]
        })
        assert r2.status_code == 401

    @pytest.mark.asyncio
    async def test_logout_with_garbage_token_still_returns_204(self, client: AsyncClient):
        """Logout is idempotent — invalid token just silently ignored."""
        r = await client.post("/api/auth/logout", json={"refresh_token": "garbage"})
        assert r.status_code == 204


# ── Forgot / Reset Password ───────────────────────────────────────────────────

class TestPasswordReset:
    """POST /api/auth/forgot-password and /api/auth/reset-password"""

    @pytest.mark.asyncio
    async def test_forgot_password_always_returns_200(self, client: AsyncClient):
        """Prevent account enumeration — same response for existing and non-existing email."""
        r1 = await client.post("/api/auth/forgot-password", json={"email": "exists@example.com"})
        r2 = await client.post("/api/auth/forgot-password", json={"email": "noexist@example.com"})
        assert r1.status_code == 200
        assert r2.status_code == 200
        # Both should have the same response structure
        assert "message" in r1.json()
        assert "message" in r2.json()

    @pytest.mark.asyncio
    async def test_reset_invalid_token_rejected(self, client: AsyncClient):
        r = await client.post("/api/auth/reset-password", json={
            "token": "fake-reset-token",
            "new_password": "NewPass1",
        })
        assert r.status_code == 400
        assert "invalid" in r.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_reset_with_valid_token_changes_password(
        self, client: AsyncClient, registered_user: dict
    ):
        """Generate a real reset token and use it."""
        from app.core.security import create_password_reset_token
        user_id = registered_user["id"]
        token   = create_password_reset_token(user_id)

        r = await client.post("/api/auth/reset-password", json={
            "token":        token,
            "new_password": "NewPass999",
        })
        assert r.status_code == 200

        # Old password should fail
        r_old = await client.post("/api/auth/login", json={
            "email": "test@example.com", "password": "TestPass1",
        })
        assert r_old.status_code == 401

        # New password should work
        r_new = await client.post("/api/auth/login", json={
            "email": "test@example.com", "password": "NewPass999",
        })
        assert r_new.status_code == 200


# ── Health ────────────────────────────────────────────────────────────────────

class TestHealth:
    """GET /health"""

    @pytest.mark.asyncio
    async def test_health_returns_200(self, client: AsyncClient):
        r = await client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert data["service"] == "aegis-web"

    @pytest.mark.asyncio
    async def test_root_returns_service_info(self, client: AsyncClient):
        r = await client.get("/")
        assert r.status_code == 200
        assert "service" in r.json()
        assert "docs" in r.json()
