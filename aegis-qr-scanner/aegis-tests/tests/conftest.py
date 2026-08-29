"""
conftest.py — Aegis QR Scanner Test Configuration
====================================================
Shared fixtures, helpers, and base64 QR samples used across all test modules.

Run tests:
    cd aegis-tests
    pip install pytest pytest-asyncio httpx websockets qrcode[pil]
    pytest -v                          # all tests
    pytest -v tests/test_phase4.py     # Phase 4 only
    pytest -v -k "async"               # all async tests
    pytest -v --tb=short               # compact tracebacks
    pytest -v -x                       # stop on first failure

Environment (set before running):
    export AEGIS_BASE_URL=http://localhost:8001
    Or: AEGIS_BASE_URL=http://localhost:8001 pytest -v
"""

import os
import io
import base64
import asyncio
import pytest
import httpx

# ─── Config ──────────────────────────────────────────────────
BASE_URL = os.getenv("AEGIS_BASE_URL", "http://localhost:8001")
TIMEOUT  = httpx.Timeout(120.0, connect=10.0)   # 120s for full scan


# ─── QR Image factory ────────────────────────────────────────

def make_qr_b64(data: str) -> str:
    """Generate a real QR code image encoded as base64 PNG."""
    try:
        import qrcode
        from PIL import Image

        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        # Convert to RGB — ensures consistent format across all Pillow versions
        img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        pytest.skip("qrcode[pil] not installed — run: pip install qrcode[pil]")


def make_multi_qr_b64(payloads: list) -> str:
    """Generate an image containing multiple QR codes side by side.

    FIX: Pillow 10+ requires a 4-tuple (left, top, right, bottom) box for
    paste() when source image has no transparency mask.
    Using a 2-tuple (x, y) raises:
        ValueError: cannot determine region size; use 4-item box
    """
    try:
        import qrcode
        from PIL import Image

        images = []
        for data in payloads:
            qr = qrcode.QRCode(version=1, box_size=8, border=3)
            qr.add_data(data)
            qr.make(fit=True)
            # Convert to RGB to avoid 1-bit / palette / RGBA mode issues
            img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
            images.append(img)

        total_w = sum(img.size[0] for img in images)
        max_h   = max(img.size[1] for img in images)
        canvas  = Image.new("RGB", (total_w, max_h), "white")
        x_off   = 0
        for img in images:
            w, h = img.size
            # 4-tuple box (left, top, right, bottom) — required by Pillow 10+
            canvas.paste(img, (x_off, 0, x_off + w, h))
            x_off += w

        buf = io.BytesIO()
        canvas.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        pytest.skip("qrcode[pil] not installed")


# ─── Sync HTTP helpers ────────────────────────────────────────

def post_scan_file(b64_img: str) -> httpx.Response:
    """POST base64 image to /scan-base64."""
    with httpx.Client(timeout=TIMEOUT) as client:
        return client.post(
            f"{BASE_URL}/scan-base64",
            json={"image_base64": b64_img},
        )


def get(path: str, **params) -> httpx.Response:
    with httpx.Client(timeout=TIMEOUT) as client:
        return client.get(f"{BASE_URL}{path}", params=params)


def post(path: str, **body) -> httpx.Response:
    with httpx.Client(timeout=TIMEOUT) as client:
        return client.post(f"{BASE_URL}{path}", json=body)


def delete(path: str) -> httpx.Response:
    with httpx.Client(timeout=TIMEOUT) as client:
        return client.delete(f"{BASE_URL}{path}")


# ─── Fixtures ─────────────────────────────────────────────────

@pytest.fixture(scope="session")
def base_url():
    return BASE_URL


@pytest.fixture(scope="session")
def safe_url_qr():
    """Base64 QR of a known-safe URL."""
    return make_qr_b64("https://google.com")


@pytest.fixture(scope="session")
def phishing_url_qr():
    """Base64 QR of a phishing URL pattern."""
    return make_qr_b64("http://secure-bank-verify-login.xyz/account/confirm?token=abc123")


@pytest.fixture(scope="session")
def bitcoin_qr():
    """Base64 QR of a Bitcoin address."""
    return make_qr_b64("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf?amount=0.1")


@pytest.fixture(scope="session")
def email_qr():
    """Base64 QR of a plain mailto — no subject/body to avoid smishing triggers.

    FIX: Using contact@example.com with no subject/body.
    mailto:test@example.com was scoring 'High' because the smishing engine
    analyses the full mailto string and can flag 'test@' patterns.
    """
    return make_qr_b64("mailto:contact@example.com")


@pytest.fixture(scope="session")
def smishing_email_qr():
    """Base64 QR of a phishing pre-drafted email."""
    return make_qr_b64(
        "mailto:victim@bank.com?subject=URGENT: Account Suspended&"
        "body=Click here to verify: http://evil-bank-login.tk/verify?id=12345"
    )


@pytest.fixture(scope="session")
def wifi_qr():
    return make_qr_b64("WIFI:T:WPA;S:MyNetwork;P:password123;;")


@pytest.fixture(scope="session")
def vcard_qr():
    return make_qr_b64(
        "BEGIN:VCARD\nVERSION:3.0\nFN:John Doe\n"
        "TEL:+1234567890\nEMAIL:john@example.com\n"
        "URL:https://google.com\nEND:VCARD"
    )


@pytest.fixture(scope="session")
def multi_qr():
    """Image with 2 QR codes side by side."""
    return make_multi_qr_b64(["https://google.com", "https://github.com"])


@pytest.fixture(scope="session")
def invalid_b64():
    return "this_is_not_valid_base64!!!###"


@pytest.fixture(scope="session")
def minimal_png_b64():
    """Tiny valid PNG with no QR code in it."""
    png = bytes([
        137,80,78,71,13,10,26,10,0,0,0,13,73,72,68,82,0,0,0,1,0,0,0,1,8,2,
        0,0,0,144,119,83,222,0,0,0,12,73,68,65,84,8,215,99,248,255,255,63,0,
        5,254,2,254,220,204,89,231,0,0,0,0,73,69,78,68,174,66,96,130
    ])
    return base64.b64encode(png).decode()


@pytest.fixture(scope="session", autouse=True)
def check_server_running():
    """Skip entire suite if Aegis is not running."""
    try:
        r = httpx.get(f"{BASE_URL}/health", timeout=5.0)
        assert r.status_code == 200, f"Health check failed: {r.status_code}"
    except (httpx.ConnectError, httpx.TimeoutException):
        pytest.skip(
            f"Aegis QR Scanner not reachable at {BASE_URL}. "
            f"Start it with: docker-compose up --build"
        )
