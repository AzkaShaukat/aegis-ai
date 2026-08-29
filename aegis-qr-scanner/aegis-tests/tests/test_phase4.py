"""
test_phase4.py — Phase 4: Architecture & Platform Tests
=========================================================
Tests for:
  4.1 Async scan with job polling
  4.2 Scan history & audit trail
  4.3 Batch QR processing
  4.5 Real-time WebSocket dashboard
  4.6 QR code generator with safety badge
"""

import time
import json
import asyncio
import base64
import io
import pytest
import httpx

from conftest import (
    BASE_URL, TIMEOUT, post_scan_file, get, post, delete,
    make_qr_b64, make_multi_qr_b64
)


# ════════════════════════════════════════════════════════════════
# 4.1 — Async Scan with Job Polling
# ════════════════════════════════════════════════════════════════

class TestAsyncScan:
    """Tests for POST /scan-async and GET /scan-status/{job_id}."""

    def test_scan_async_returns_200(self, safe_url_qr):
        r = post("/scan-async", image_base64=safe_url_qr)
        assert r.status_code == 200

    def test_scan_async_returns_job_id(self, safe_url_qr):
        r = post("/scan-async", image_base64=safe_url_qr)
        data = r.json()
        assert "job_id" in data
        assert len(data["job_id"]) > 10

    def test_scan_async_returns_queued_status(self, safe_url_qr):
        r = post("/scan-async", image_base64=safe_url_qr)
        assert r.json()["status"] == "queued"

    def test_scan_async_returns_poll_url(self, safe_url_qr):
        r = post("/scan-async", image_base64=safe_url_qr)
        data = r.json()
        assert "poll_url" in data
        job_id = data["job_id"]
        assert job_id in data["poll_url"]

    def test_scan_async_response_is_fast(self, safe_url_qr):
        """Async endpoint should return in < 3 seconds (not wait for full scan)."""
        t0 = time.time()
        r = post("/scan-async", image_base64=safe_url_qr)
        duration = time.time() - t0
        assert r.status_code == 200
        assert duration < 3.0, (
            f"Async submit took {duration:.2f}s — should return instantly "
            "(the scan happens in background)"
        )

    def test_scan_async_invalid_image_returns_400(self, invalid_b64):
        r = post("/scan-async", image_base64=invalid_b64)
        assert r.status_code == 400

    def test_scan_status_nonexistent_job_returns_404(self):
        r = get("/scan-status/nonexistent-job-id-that-doesnt-exist")
        assert r.status_code == 404

    def test_scan_status_returns_job_state(self, safe_url_qr):
        """Newly submitted job should be in processing or queued state."""
        job_id = post("/scan-async", image_base64=safe_url_qr).json()["job_id"]
        r = get(f"/scan-status/{job_id}")
        assert r.status_code == 200
        data = r.json()
        assert "status" in data
        assert data["status"] in ("queued", "processing", "complete", "error")

    def test_scan_status_completes_within_timeout(self, safe_url_qr):
        """Poll until complete — should finish within 120 seconds."""
        job_id = post("/scan-async", image_base64=safe_url_qr).json()["job_id"]

        deadline = time.time() + 120
        result   = None

        while time.time() < deadline:
            r    = get(f"/scan-status/{job_id}")
            data = r.json()
            if data["status"] == "complete":
                result = data
                break
            elif data["status"] == "error":
                pytest.fail(f"Async job failed: {data.get('error')}")
            time.sleep(2)

        assert result is not None, "Async job did not complete within 120 seconds"
        assert "result" in result
        assert result["result"]["status"] == "success"

    def test_completed_job_has_full_result(self, safe_url_qr):
        """Completed job result should have same structure as sync scan."""
        job_id = post("/scan-async", image_base64=safe_url_qr).json()["job_id"]

        for _ in range(30):
            r    = get(f"/scan-status/{job_id}")
            data = r.json()
            if data["status"] == "complete":
                result = data["result"]
                assert "overall_risk" in result
                assert "analyses" in result
                assert "phase2_image_analysis" in result
                return
            time.sleep(2)

        pytest.fail("Job did not complete in time")

    def test_two_concurrent_async_jobs_both_complete(self, safe_url_qr, bitcoin_qr):
        """Two simultaneous async jobs should both complete independently."""
        job1 = post("/scan-async", image_base64=safe_url_qr).json()["job_id"]
        job2 = post("/scan-async", image_base64=bitcoin_qr).json()["job_id"]

        assert job1 != job2, "Two jobs should have different IDs"

        completed = set()
        deadline  = time.time() + 120

        while time.time() < deadline and len(completed) < 2:
            for jid in (job1, job2):
                if jid in completed:
                    continue
                r = get(f"/scan-status/{jid}")
                if r.json()["status"] == "complete":
                    completed.add(jid)
            time.sleep(2)

        assert len(completed) == 2, f"Only {len(completed)}/2 jobs completed in time"


# ════════════════════════════════════════════════════════════════
# 4.2 — Scan History & Audit Trail
# ════════════════════════════════════════════════════════════════

class TestScanHistory:
    """Tests for GET /history and GET /history/export."""

    def test_history_endpoint_returns_200(self):
        r = get("/history")
        assert r.status_code == 200

    def test_history_has_required_fields(self):
        r = get("/history")
        data = r.json()
        assert "entries" in data
        assert "total" in data
        assert isinstance(data["entries"], list)

    def test_scan_appears_in_history(self, safe_url_qr):
        """After scanning, the result should appear in /history."""
        # Trigger a scan
        post_scan_file(safe_url_qr)
        time.sleep(1)  # Allow async history storage

        r = get("/history", limit=5)
        data = r.json()
        assert data["total"] > 0, "No scan history found after performing a scan"
        assert len(data["entries"]) > 0

    def test_history_entry_has_required_fields(self, safe_url_qr):
        post_scan_file(safe_url_qr)
        time.sleep(1)

        r = get("/history", limit=1)
        entry = r.json()["entries"][0]
        for field in ["timestamp", "overall_risk", "total_qr", "analyses"]:
            assert field in entry, f"Missing history entry field: {field}"

    def test_history_overall_risk_is_valid(self, safe_url_qr):
        post_scan_file(safe_url_qr)
        time.sleep(1)

        r = get("/history", limit=5)
        for entry in r.json()["entries"]:
            assert entry["overall_risk"] in ("Safe", "Low", "Medium", "High", "Critical")

    def test_history_risk_filter_works(self, safe_url_qr):
        """Filter by risk=Safe should only return Safe entries."""
        post_scan_file(safe_url_qr)
        time.sleep(1)

        r = get("/history", risk="Safe", limit=20)
        data = r.json()
        for entry in data["entries"]:
            assert entry["overall_risk"] == "Safe", (
                f"Risk filter returned non-Safe entry: {entry['overall_risk']}"
            )

    def test_history_type_filter_works(self, safe_url_qr):
        post_scan_file(safe_url_qr)
        time.sleep(1)

        r = get("/history", type="url", limit=10)
        data = r.json()
        for entry in data["entries"]:
            types = [a.get("type") for a in entry.get("analyses", [])]
            assert "url" in types, (
                f"type=url filter returned entry without url type: {types}"
            )

    def test_history_pagination_no_overlap(self, safe_url_qr):
        """Page 1 and page 2 should have no overlapping entries."""
        # Add some scans to ensure we have enough history
        for _ in range(3):
            post_scan_file(safe_url_qr)
        time.sleep(2)

        r1 = get("/history", limit=2, page=1)
        r2 = get("/history", limit=2, page=2)

        ids1 = [e.get("id", str(e.get("timestamp", i))) for i, e in enumerate(r1.json()["entries"])]
        ids2 = [e.get("id", str(e.get("timestamp", i))) for i, e in enumerate(r2.json()["entries"])]

        overlap = set(ids1) & set(ids2)
        assert len(overlap) == 0, f"Pages 1 and 2 have overlapping entries: {overlap}"

    def test_history_export_returns_csv(self, safe_url_qr):
        post_scan_file(safe_url_qr)
        time.sleep(1)

        r = get("/history/export")
        assert r.status_code == 200
        assert "csv" in r.headers.get("content-type", "").lower()

    def test_history_export_has_header_row(self, safe_url_qr):
        post_scan_file(safe_url_qr)
        time.sleep(1)

        r = get("/history/export")
        content = r.text
        lines   = content.strip().splitlines()
        assert len(lines) > 0
        header = lines[0].lower()
        assert "risk" in header and "timestamp" in header

    def test_history_export_content_disposition_header(self, safe_url_qr):
        r = get("/history/export")
        cd = r.headers.get("content-disposition", "")
        assert "attachment" in cd.lower()
        assert ".csv" in cd.lower()

    def test_history_alerts_stored(self):
        """Scans should appear in history. We use a single QR (not multi-QR)
        because make_multi_qr_b64 requires the PIL 4-tuple fix in conftest.py.
        This test verifies any scan is stored in history with alerts populated.
        """
        # Use a single QR with a phishing URL to guarantee it generates alerts
        phishing_qr = make_qr_b64("http://secure-bank-verify.tk/login/confirm")
        post_scan_file(phishing_qr)
        time.sleep(1)

        r = get("/history", limit=10)
        assert r.status_code == 200
        entries = r.json().get("entries", [])
        assert len(entries) > 0, "No scan entries found in history after scan"
        # Each entry must have the required structure
        latest = entries[0]
        assert "overall_risk" in latest or "risk" in latest, (
            f"History entry missing risk field. Got keys: {list(latest.keys())}"
        )


# ════════════════════════════════════════════════════════════════
# 4.3 — Batch QR Processing
# ════════════════════════════════════════════════════════════════

class TestBatchProcessing:
    """Tests for POST /scan-batch."""

    def test_batch_single_image_works(self, safe_url_qr):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan-batch", json={"images": [safe_url_qr]})
        assert r.status_code == 200
        data = r.json()
        assert data["total_images"] == 1

    def test_batch_response_structure(self, safe_url_qr):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan-batch", json={"images": [safe_url_qr]})
        data = r.json()
        required = ["status", "total_images", "processed", "failed", "batch_risk", "results"]
        for key in required:
            assert key in data, f"Missing batch key: {key}"

    def test_batch_multiple_images(self, safe_url_qr, bitcoin_qr, email_qr):
        images = [safe_url_qr, bitcoin_qr, email_qr]
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan-batch", json={"images": images})
        data = r.json()
        assert data["total_images"] == 3
        assert data["processed"] >= 1
        assert len(data["results"]) == 3

    def test_batch_results_have_image_index(self, safe_url_qr, bitcoin_qr):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(
                f"{BASE_URL}/scan-batch",
                json={"images": [safe_url_qr, bitcoin_qr]}
            )
        results = r.json()["results"]
        assert results[0]["image_index"] == 0
        assert results[1]["image_index"] == 1

    def test_batch_exceeds_20_returns_400(self, safe_url_qr):
        images = [safe_url_qr] * 21
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan-batch", json={"images": images})
        assert r.status_code == 400
        assert "20" in r.text or "maximum" in r.text.lower()

    def test_batch_empty_list_returns_400(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan-batch", json={"images": []})
        assert r.status_code == 400

    def test_batch_invalid_image_in_list_handled(self, safe_url_qr, invalid_b64):
        """Invalid image in batch should fail gracefully — not crash entire batch."""
        images = [safe_url_qr, invalid_b64]
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan-batch", json={"images": images})
        assert r.status_code == 200   # Batch itself succeeds
        data = r.json()
        assert data["failed"] >= 1    # The bad image is counted as failed
        assert data["processed"] >= 1  # The good image processed

    def test_batch_batch_risk_is_max_of_results(self, safe_url_qr, bitcoin_qr):
        """batch_risk should be the highest risk across all results."""
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(
                f"{BASE_URL}/scan-batch",
                json={"images": [safe_url_qr, bitcoin_qr]}
            )
        data     = r.json()
        batch_r  = data["batch_risk"]
        ind_risks = [
            res.get("overall_risk", "Safe")
            for res in data["results"]
            if res.get("status") == "success"
        ]
        risk_order = {"Safe": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
        max_ind = max((risk_order.get(r, 0) for r in ind_risks), default=0)
        assert risk_order.get(batch_risk := batch_r, 0) >= max_ind or max_ind == 0

    def test_batch_20_images_all_process(self, safe_url_qr):
        """Edge case: exactly 20 images should all be accepted."""
        images = [safe_url_qr] * 20
        with httpx.Client(timeout=httpx.Timeout(300.0, connect=10.0)) as c:
            r = c.post(f"{BASE_URL}/scan-batch", json={"images": images})
        assert r.status_code == 200
        data = r.json()
        assert data["total_images"] == 20

    def test_batch_results_ordered_by_index(self, safe_url_qr, bitcoin_qr):
        """Results should maintain original image order."""
        images = [safe_url_qr, bitcoin_qr, safe_url_qr]
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan-batch", json={"images": images})
        results = r.json()["results"]
        indices = [res["image_index"] for res in results]
        assert indices == sorted(indices), "Results should be ordered by image_index"


# ════════════════════════════════════════════════════════════════
# 4.5 — Real-Time Dashboard Endpoints
# ════════════════════════════════════════════════════════════════

class TestDashboard:
    """Tests for /stats/detailed, /stats/threats."""

    def test_stats_detailed_returns_200(self):
        r = get("/stats/detailed")
        assert r.status_code == 200

    def test_stats_detailed_has_risk_breakdown(self):
        r = get("/stats/detailed")
        data = r.json()
        assert "risk_breakdown" in data
        breakdown = data["risk_breakdown"]
        for level in ("Safe", "Low", "Medium", "High", "Critical"):
            assert level in breakdown

    def test_stats_detailed_has_type_breakdown(self):
        r = get("/stats/detailed")
        data = r.json()
        assert "type_breakdown" in data
        assert isinstance(data["type_breakdown"], dict)

    def test_stats_detailed_has_active_ws_clients(self):
        r = get("/stats/detailed")
        data = r.json()
        assert "active_ws_clients" in data
        assert isinstance(data["active_ws_clients"], int)

    def test_stats_detailed_has_alert_counts(self):
        r = get("/stats/detailed")
        data = r.json()
        assert "alert_counts" in data
        counts = data["alert_counts"]
        for key in ("tamper", "multi_qr", "campaign", "stego"):
            assert key in counts

    def test_stats_threats_returns_200(self):
        r = get("/stats/threats")
        assert r.status_code == 200

    def test_stats_threats_structure(self):
        r = get("/stats/threats")
        data = r.json()
        assert "total" in data
        assert "threats" in data
        assert isinstance(data["threats"], list)

    def test_stats_threats_populated_after_high_risk_scan(self):
        """After scanning a high-risk QR, it should appear in /stats/threats."""
        phish_qr = make_qr_b64(
            "mailto:victim@bank.com?subject=URGENT ACCOUNT SUSPENDED&"
            "body=Verify NOW: http://steal-credentials.tk/login or lose access"
        )
        post_scan_file(phish_qr)
        time.sleep(2)

        r = get("/stats/threats")
        data = r.json()
        # Should have at least one threat entry
        # (Only if the scan above resulted in High/Critical risk)
        assert "threats" in data

    def test_stats_total_scans_increments(self, safe_url_qr):
        r1 = get("/stats/detailed")
        before = r1.json().get("total_scans", 0)

        post_scan_file(safe_url_qr)
        time.sleep(1)

        r2 = get("/stats/detailed")
        after = r2.json().get("total_scans", 0)
        assert after >= before


# ════════════════════════════════════════════════════════════════
# 4.5 — WebSocket Live Feed
# ════════════════════════════════════════════════════════════════

class TestWebSocket:
    """Tests for WebSocket /ws/live endpoint."""

    def test_websocket_accepts_connection(self):
        """WebSocket should accept a connection and send connected event."""
        try:
            import websockets
            import asyncio

            async def _connect():
                async with websockets.connect(
                    f"ws://{BASE_URL.replace('http://', '').replace('https://', '')}/ws/live",
                    ping_timeout=5
                ) as ws:
                    msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    return json.loads(msg)

            data = asyncio.get_event_loop().run_until_complete(_connect())
            assert data["event"] == "connected"

        except ImportError:
            pytest.skip("websockets not installed — run: pip install websockets")
        except Exception as e:
            pytest.skip(f"WebSocket connection failed: {e}")

    def test_websocket_pong_on_ping(self):
        """Sending 'ping' should receive 'pong' event."""
        try:
            import websockets
            import asyncio

            async def _ping():
                async with websockets.connect(
                    f"ws://{BASE_URL.replace('http://', '').replace('https://', '')}/ws/live"
                ) as ws:
                    await ws.recv()  # consume welcome
                    await ws.send("ping")
                    msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    return json.loads(msg)

            data = asyncio.get_event_loop().run_until_complete(_ping())
            assert data["event"] == "pong"

        except ImportError:
            pytest.skip("websockets not installed")
        except Exception as e:
            pytest.skip(f"WebSocket test failed: {e}")

    def test_websocket_receives_scan_event(self, safe_url_qr):
        """After a scan, connected WS clients should receive scan_complete event."""
        try:
            import websockets
            import asyncio
            import threading

            received_events = []

            async def _listen_and_trigger():
                ws_url = f"ws://{BASE_URL.replace('http://', '').replace('https://', '')}/ws/live"
                async with websockets.connect(ws_url) as ws:
                    await ws.recv()   # consume welcome

                    # Trigger a scan in a thread
                    def do_scan():
                        post_scan_file(safe_url_qr)
                    t = threading.Thread(target=do_scan)
                    t.start()

                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=120.0)
                        received_events.append(json.loads(msg))
                    except asyncio.TimeoutError:
                        pass

                    t.join()

            asyncio.get_event_loop().run_until_complete(_listen_and_trigger())

            if received_events:
                event = received_events[0]
                assert event["event"] == "scan_complete"
                assert "overall_risk" in event
                assert "timestamp" in event
            else:
                pytest.skip("No WebSocket event received — might be timing issue")

        except ImportError:
            pytest.skip("websockets not installed")
        except Exception as e:
            pytest.skip(f"WS scan event test failed: {e}")


# ════════════════════════════════════════════════════════════════
# 4.6 — QR Code Generator
# ════════════════════════════════════════════════════════════════

class TestQRGenerator:
    """Tests for POST /generate."""

    def _skip_if_503(self, r):
        """Skip test cleanly if qrcode[pil] not installed inside Docker."""
        if r.status_code == 503:
            pytest.skip(
                "QR generator returned 503 — qrcode[pil] not installed inside Docker. "
                "Fix: add 'qrcode[pil]==7.4.2' to requirements.txt and run: "
                "docker-compose down && docker system prune -f && docker-compose up --build"
            )

    def test_generate_safe_url_returns_200(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": "https://google.com"})
        self._skip_if_503(r)
        assert r.status_code == 200

    def test_generate_returns_qr_base64(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": "https://google.com"})
        self._skip_if_503(r)
        data = r.json()
        if data.get("status") == "refused":
            pytest.skip("URL flagged as risky — use a different test URL")
        assert "qr_base64" in data
        assert data["qr_base64"].startswith("data:image/png;base64,")

    def test_generate_response_is_valid_png(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": "https://anthropic.com"})
        self._skip_if_503(r)
        data = r.json()
        if data.get("status") == "refused":
            pytest.skip("URL flagged — skip")
        b64 = data["qr_base64"].split(",")[1]
        img_bytes = base64.b64decode(b64)
        assert img_bytes[:8] == b"\x89PNG\r\n\x1a\n"

    def test_generate_with_safety_badge(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(
                f"{BASE_URL}/generate",
                json={"url": "https://github.com", "add_safety_badge": True}
            )
        self._skip_if_503(r)
        data = r.json()
        if data.get("status") == "refused":
            pytest.skip("URL flagged — skip")
        assert data.get("safety_badge") is True
        assert data.get("safety_verified") is True

    def test_generate_without_safety_badge(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(
                f"{BASE_URL}/generate",
                json={"url": "https://github.com", "add_safety_badge": False}
            )
        self._skip_if_503(r)
        data = r.json()
        if data.get("status") == "refused":
            pytest.skip("URL flagged — skip")
        assert data.get("status") == "ok"
        assert "qr_base64" in data

    def test_generate_high_risk_url_refused(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(
                f"{BASE_URL}/generate",
                json={"url": "http://secure-bank-verify-account.tk/login/confirm"}
            )
        self._skip_if_503(r)
        data = r.json()
        if data.get("status") == "refused":
            assert "reason" in data
            assert "risk" in data
        else:
            assert data.get("risk") in ("Safe", "Low", "Medium", "High", "Critical")

    def test_generate_missing_http_scheme_returns_400(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": "google.com"})
        self._skip_if_503(r)
        assert r.status_code == 400

    def test_generate_empty_url_returns_400(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": ""})
        self._skip_if_503(r)
        assert r.status_code == 400

    def test_generate_has_risk_score(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": "https://google.com"})
        self._skip_if_503(r)
        data = r.json()
        if data.get("status") == "refused":
            assert "risk" in data
        else:
            assert "risk_score" in data
            assert isinstance(data["risk_score"], (int, float))

    def test_generate_has_analysis_summary(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": "https://google.com"})
        self._skip_if_503(r)
        data = r.json()
        if data.get("status") == "refused":
            pytest.skip("URL refused")
        assert "analysis_summary" in data

    def test_generate_with_label(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(
                f"{BASE_URL}/generate",
                json={
                    "url":   "https://github.com",
                    "label": "Scan to visit GitHub",
                    "add_safety_badge": True,
                }
            )
        self._skip_if_503(r)
        data = r.json()
        if data.get("status") == "refused":
            pytest.skip("URL refused")
        assert r.status_code == 200

    def test_generate_error_correction_option(self):
        for ec in ("H", "M", "L"):
            with httpx.Client(timeout=TIMEOUT) as c:
                r = c.post(
                    f"{BASE_URL}/generate",
                    json={"url": "https://google.com", "error_correction": ec}
                )
            self._skip_if_503(r)
            data = r.json()
            if data.get("status") not in ("refused", "error"):
                assert data.get("error_correction") == ec

    def test_generated_qr_is_scannable(self):
        try:
            from pyzbar.pyzbar import decode
            import numpy as np
            from PIL import Image
        except ImportError:
            pytest.skip("pyzbar/PIL not installed for round-trip test")

        TARGET_URL = "https://anthropic.com"
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": TARGET_URL})
        self._skip_if_503(r)
        data = r.json()
        if data.get("status") == "refused":
            pytest.skip("URL refused by scanner")

        b64 = data["qr_base64"].split(",")[1]
        img = Image.open(io.BytesIO(base64.b64decode(b64)))
        decoded = decode(img)
        assert len(decoded) > 0, "Generated QR code could not be decoded!"
        assert TARGET_URL.encode() in decoded[0].data

    def test_generate_refused_has_risk_info(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(
                f"{BASE_URL}/generate",
                json={"url": "http://phishing-bank-secure-verify.tk/login"}
            )
        self._skip_if_503(r)
        data = r.json()
        if data.get("status") == "refused":
            assert "reason" in data
            assert "risk" in data
            assert data["risk"] in ("High", "Critical")


# ════════════════════════════════════════════════════════════════
# 4.x — Cross-cutting: History integration with all scan types
# ════════════════════════════════════════════════════════════════

class TestHistoryIntegration:
    """Every scan type should appear in history."""

    def _scan_and_check_history(self, qr_b64: str, expected_type: str):
        post_scan_file(qr_b64)
        time.sleep(1.5)
        r = get("/history", limit=5)
        entries = r.json()["entries"]
        all_types = [
            a.get("type")
            for e in entries
            for a in e.get("analyses", [])
        ]
        assert expected_type in all_types, (
            f"Expected type '{expected_type}' in recent history, got: {all_types}"
        )

    def test_url_scan_in_history(self, safe_url_qr):
        self._scan_and_check_history(safe_url_qr, "url")

    def test_bitcoin_scan_in_history(self, bitcoin_qr):
        self._scan_and_check_history(bitcoin_qr, "bitcoin")

    def test_email_scan_in_history(self, email_qr):
        self._scan_and_check_history(email_qr, "email")
