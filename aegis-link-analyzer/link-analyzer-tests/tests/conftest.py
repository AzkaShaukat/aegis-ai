"""
conftest.py — Aegis Link Analyzer Test Configuration
======================================================
Shared fixtures, helpers, and URL samples used across all test modules.

Run tests:
    cd link-analyzer-tests
    pip install pytest pytest-asyncio httpx
    pytest -v

    # Set base URL if different port:
    LINK_ANALYZER_URL=http://localhost:8000 pytest -v

RATE LIMIT NOTE
---------------
The /scan endpoint enforces a 5 req/min sliding-window rate limit.
Running the full test suite fires 100+ scan calls in rapid succession,
which exhausts the bucket after the first ~5 requests. Every helper
that calls /scan therefore uses _request_with_retry() which:
  1. Makes the request
  2. If 429 is returned, reads the Retry-After header (default 62 s)
  3. Sleeps for that duration
  4. Retries up to MAX_RETRIES times before raising

This adds time to the suite but guarantees every test gets a real
response instead of {'detail': 'Too Many Requests'}.
"""

import os
import time
import pytest
import httpx

# ─── Config ──────────────────────────────────────────────────
BASE_URL  = os.getenv("LINK_ANALYZER_URL", "http://localhost:8000")
TIMEOUT   = httpx.Timeout(120.0, connect=10.0)   # full scan can take ~60s

# Retry parameters for rate-limited endpoints
MAX_RETRIES     = 5       # maximum number of retry attempts
DEFAULT_WAIT_S  = 62      # seconds to wait when Retry-After header is absent


# ─── Rate-limit-aware HTTP helpers ────────────────────────────

def _request_with_retry(method: str, url: str, **kwargs) -> httpx.Response:
    """
    Execute an HTTP request and automatically retry on HTTP 429.

    When the server returns 429 Too Many Requests:
      - Reads the Retry-After header (integer seconds) if present
      - Falls back to DEFAULT_WAIT_S if the header is missing
      - Sleeps and retries up to MAX_RETRIES times

    All other status codes (including 4xx/5xx) are returned immediately.
    """
    for attempt in range(MAX_RETRIES + 1):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = getattr(c, method)(url, **kwargs)

        if r.status_code != 429:
            return r

        # 429 received — determine how long to wait
        retry_after_raw = r.headers.get("Retry-After", "")
        try:
            wait_seconds = int(retry_after_raw)
        except (ValueError, TypeError):
            wait_seconds = DEFAULT_WAIT_S

        if attempt < MAX_RETRIES:
            print(
                f"\n  [rate-limit] 429 on {method.upper()} {url} "
                f"(attempt {attempt + 1}/{MAX_RETRIES}) — "
                f"waiting {wait_seconds}s before retry..."
            )
            time.sleep(wait_seconds)
        else:
            # Exhausted retries — return the 429 so the test can handle it
            return r

    return r   # unreachable, but satisfies type checkers


def get(path: str, **params) -> httpx.Response:
    return _request_with_retry("get", f"{BASE_URL}{path}", params=params)


def post(path: str, body: dict) -> httpx.Response:
    return _request_with_retry("post", f"{BASE_URL}{path}", json=body)


def scan(url: str) -> httpx.Response:
    return post("/scan", {"url": url})


def scan_json(url: str) -> dict:
    return scan(url).json()


# ─── URL Fixtures ─────────────────────────────────────────────

# Known-safe URLs — major trusted domains
SAFE_URLS = [
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://stackoverflow.com",
]

# Clearly phishing-pattern URLs — suspicious TLD + keywords
PHISHING_URLS = [
    "http://paypal-secure-verify-account.tk/login/confirm",
    "http://amazon-account-update.xyz/billing/verify",
    "http://secure-bank-login-verify.ml/account",
]

# IP-based URLs — always suspicious
IP_URLS = [
    "http://185.234.218.53/admin/login.php",
    "http://192.168.0.1/setup",
]

# URL shorteners
SHORTENER_URLS = [
    "https://bit.ly/3example",
    "https://tinyurl.com/testlink",
]

# Malware test URL provided by Google for testing (safe to use)
GOOGLE_MALWARE_TEST = "http://malware.testing.google.test/testing/malware/"

# Bare domain — should be auto-normalised to https://
BARE_DOMAIN = "google.com"


# ─── Fixtures ─────────────────────────────────────────────────

@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture(scope="session")
def safe_scan():
    """Pre-run scan of google.com — reused across tests (scope=session)."""
    return scan_json("https://google.com")


@pytest.fixture(scope="session")
def phishing_scan():
    """Pre-run scan of a phishing-pattern URL (scope=session)."""
    return scan_json("http://paypal-secure-verify-account.tk/login/confirm")


@pytest.fixture(scope="session", autouse=True)
def check_server_running():
    """Skip entire suite if Link Analyzer is not reachable."""
    try:
        r = httpx.get(f"{BASE_URL}/health", timeout=5.0)
        assert r.status_code == 200
    except (httpx.ConnectError, httpx.TimeoutException, AssertionError):
        pytest.skip(
            f"\n\nLink Analyzer not reachable at {BASE_URL}.\n"
            f"Start it with:  cd aegis-link-analyzer && docker-compose up --build\n"
            f"Then re-run:    pytest -v\n"
        )
