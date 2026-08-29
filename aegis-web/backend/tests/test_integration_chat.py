"""tests/test_integration_chat.py — Integration tests for chat/history endpoints."""
import pytest
from httpx import AsyncClient


class TestChatSessions:
    """GET/PATCH/DELETE /api/chat/sessions/*"""

    @pytest.mark.asyncio
    async def test_list_sessions_empty_for_new_user(
        self, client: AsyncClient, auth_headers: dict
    ):
        r = await client.get("/api/chat/sessions", headers=auth_headers)
        assert r.status_code == 200
        assert r.json() == []

    @pytest.mark.asyncio
    async def test_get_nonexistent_session_returns_404(
        self, client: AsyncClient, auth_headers: dict
    ):
        r = await client.get(
            "/api/chat/sessions/00000000-0000-0000-0000-000000000000",
            headers=auth_headers,
        )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_sessions_require_auth(self, client: AsyncClient):
        r = await client.get("/api/chat/sessions")
        assert r.status_code in (401, 403)


class TestScanHistory:
    """GET /api/history/*"""

    @pytest.mark.asyncio
    async def test_history_empty_for_new_user(
        self, client: AsyncClient, auth_headers: dict
    ):
        r = await client.get("/api/history/30days", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["total"] == 0
        assert data["entries"] == []
        assert data["period_days"] == 30

    @pytest.mark.asyncio
    async def test_stats_zero_for_new_user(
        self, client: AsyncClient, auth_headers: dict
    ):
        r = await client.get("/api/history/stats", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["total_scans"] == 0
        assert data["threats_found"] == 0
        assert data["links_scanned"] == 0

    @pytest.mark.asyncio
    async def test_history_requires_auth(self, client: AsyncClient):
        r = await client.get("/api/history/30days")
        assert r.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_stats_requires_auth(self, client: AsyncClient):
        r = await client.get("/api/history/stats")
        assert r.status_code in (401, 403)
