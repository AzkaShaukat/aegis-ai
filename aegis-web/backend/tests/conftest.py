"""tests/conftest.py — Shared pytest fixtures for unit and integration tests."""
import asyncio
import os
import pytest
import pytest_asyncio
from typing import AsyncGenerator

# Set test environment BEFORE importing app modules
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://aegis:aegispass@localhost:5432/aegis_web_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/9")  # DB 9 = test isolation
os.environ.setdefault("REDIS_RATE_LIMIT_URL", "redis://localhost:6379/9")
os.environ.setdefault("JWT_SECRET", "test-secret-key-do-not-use-in-production-32chars")
os.environ.setdefault("EMAIL_ENABLED", "false")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("LOG_LEVEL", "WARNING")  # quieter test output

# Clear settings cache so test env vars take effect
from app.core.config import get_settings
get_settings.cache_clear()

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.core.database import Base, get_db
from app.main import app


# ── Test database engine (separate from production) ────────────────────────────
TEST_DB_URL = os.environ["DATABASE_URL"]

test_engine = create_async_engine(TEST_DB_URL, echo=False)
TestSessionLocal = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(scope="session")
def event_loop():
    """Use a single event loop for the entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_db():
    """Create all tables in the test database before any test runs."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)   # clean slate
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Cleanup after all tests
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(autouse=True)
async def clean_tables():
    """Clear all rows between tests for isolation."""
    yield
    async with test_engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provide a clean DB session for unit tests."""
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """HTTP test client using the test database."""
    # Override the DB dependency
    async def _override_get_db():
        async with TestSessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db] = _override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


# ── Reusable test data helpers ─────────────────────────────────────────────────

TEST_USER = {
    "email":        "test@example.com",
    "password":     "TestPass1",
    "display_name": "Test User",
}


@pytest_asyncio.fixture
async def registered_user(client: AsyncClient) -> dict:
    """Create and return a registered user."""
    r = await client.post("/api/auth/register", json=TEST_USER)
    assert r.status_code == 201, f"Register failed: {r.text}"
    return r.json()


@pytest_asyncio.fixture
async def auth_headers(client: AsyncClient, registered_user: dict) -> dict:
    """Return Authorization headers for an authenticated user."""
    r = await client.post("/api/auth/login", json={
        "email":    TEST_USER["email"],
        "password": TEST_USER["password"],
    })
    assert r.status_code == 200, f"Login failed: {r.text}"
    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def auth_tokens(client: AsyncClient, registered_user: dict) -> dict:
    """Return full token pair for refresh/logout tests."""
    r = await client.post("/api/auth/login", json={
        "email":    TEST_USER["email"],
        "password": TEST_USER["password"],
    })
    assert r.status_code == 200
    return r.json()
