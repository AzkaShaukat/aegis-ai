"""
test_bulk_scan.py — POST /scan/bulk Tests
==========================================
Tests for: structure, concurrent processing, risk aggregation,
           limits (10 URL max), mixed results, error handling.
"""

import time
import pytest
import httpx
from conftest import BASE_URL, TIMEOUT, post, SAFE_URLS, PHISHING_URLS


def bulk_scan(urls: list) -> httpx.Response:
    return post("/scan/bulk", {"urls": urls})


def bulk_json(urls: list) -> dict:
    return bulk_scan(urls).json()


# ════════════════════════════════════════════════════════════════
# 1 — Response Structure
# ════════════════════════════════════════════════════════════════

class TestBulkScanStructure:

    def test_bulk_returns_200(self):
        r = bulk_scan(["https://google.com"])
        assert r.status_code == 200

    def test_bulk_has_required_top_level_fields(self):
        data = bulk_json(["https://google.com"])
        for field in ["total_urls", "completed", "failed",
                      "results", "scan_duration_seconds"]:
            assert field in data, f"Missing bulk field: {field}"

    def test_total_urls_matches_input(self):
        urls = ["https://google.com", "https://github.com"]
        data = bulk_json(urls)
        assert data["total_urls"] == 2

    def test_results_length_matches_total_urls(self):
        urls = ["https://google.com", "https://github.com"]
        data = bulk_json(urls)
        assert len(data["results"]) == 2

    def test_completed_plus_failed_equals_total(self):
        data = bulk_json(["https://google.com", "https://github.com"])
        assert data["completed"] + data["failed"] == data["total_urls"]

    def test_scan_duration_seconds_is_positive(self):
        data = bulk_json(["https://google.com"])
        assert data["scan_duration_seconds"] > 0

    def test_highest_risk_url_is_string_or_none(self):
        data = bulk_json(["https://google.com"])
        assert data.get("highest_risk_url") is None or \
               isinstance(data["highest_risk_url"], str)


# ════════════════════════════════════════════════════════════════
# 2 — Per-URL Result Structure
# ════════════════════════════════════════════════════════════════

class TestBulkResultStructure:

    def test_each_result_has_required_fields(self):
        data = bulk_json(["https://google.com"])
        for result in data["results"]:
            for field in ["url", "status"]:
                assert field in result, f"Missing per-result field: {field}"

    def test_completed_results_have_risk_level(self):
        data = bulk_json(["https://google.com"])
        for result in data["results"]:
            if result["status"] == "complete":
                assert result["risk_level"] in (
                    "Safe", "Low Risk", "Medium Risk", "High Risk"
                )

    def test_completed_results_have_confidence_score(self):
        data = bulk_json(["https://google.com"])
        for result in data["results"]:
            if result["status"] == "complete":
                assert result["confidence_score"] is not None
                assert 0.0 <= result["confidence_score"] <= 100.0

    def test_completed_results_have_total_flags(self):
        data = bulk_json(["https://google.com"])
        for result in data["results"]:
            if result["status"] == "complete":
                assert isinstance(result.get("total_flags"), int)
                assert result["total_flags"] >= 0

    def test_result_url_matches_input_url(self):
        url = "https://google.com"
        data = bulk_json([url])
        assert data["results"][0]["url"] == url


# ════════════════════════════════════════════════════════════════
# 3 — Limits & Validation
# ════════════════════════════════════════════════════════════════

class TestBulkLimits:

    def test_11_urls_returns_400(self):
        urls = ["https://example.com"] * 11
        r = bulk_scan(urls)
        assert r.status_code in (400, 422), \
            f"Expected 400/422 for >10 URLs, got {r.status_code}"

    def test_10_urls_is_accepted(self):
        urls = [f"https://example{i}.com" for i in range(10)]
        r = bulk_scan(urls)
        assert r.status_code == 200

    def test_empty_list_returns_400(self):
        r = bulk_scan([])
        assert r.status_code in (400, 422)

    def test_missing_urls_field_returns_422(self):
        r = post("/scan/bulk", {})
        assert r.status_code == 422

    def test_bare_domains_auto_normalized(self):
        """Bare domains should be accepted and normalized."""
        data = bulk_json(["google.com", "github.com"])
        assert data["total_urls"] == 2
        assert data["completed"] >= 1

    def test_single_url_works(self):
        data = bulk_json(["https://google.com"])
        assert data["total_urls"] == 1
        assert data["completed"] == 1
        assert data["failed"] == 0


# ════════════════════════════════════════════════════════════════
# 4 — Concurrent Processing
# ════════════════════════════════════════════════════════════════

class TestBulkConcurrency:

    def test_two_urls_faster_than_two_sequential_scans(self):
        """
        Bulk scan of 2 URLs should take less than 2x a single scan.
        All scans run concurrently via asyncio.gather().
        """
        from conftest import scan

        # Time a single scan
        t0 = time.time()
        scan("https://google.com")
        single_time = time.time() - t0

        # Time a bulk of 2
        t0 = time.time()
        bulk_scan(["https://google.com", "https://github.com"])
        bulk_time = time.time() - t0

        # Bulk should be < 1.8x single (not 2x, due to concurrency)
        assert bulk_time < single_time * 1.8, (
            f"Bulk ({bulk_time:.1f}s) is not faster than 2x sequential "
            f"({single_time * 2:.1f}s) — may not be running concurrently"
        )


# ════════════════════════════════════════════════════════════════
# 5 — Risk Aggregation
# ════════════════════════════════════════════════════════════════

class TestBulkRiskAggregation:

    RISK_ORDER = {"Safe": 1, "Low Risk": 2, "Medium Risk": 3, "High Risk": 4}

    def test_highest_risk_url_is_correct(self):
        """highest_risk_url should point to the riskiest URL in the batch."""
        urls = ["https://google.com",
                "http://paypal-verify-login.tk/account"]
        data = bulk_json(urls)
        if data["highest_risk_url"] and data["completed"] >= 2:
            # The phishing-pattern URL should be the highest risk
            assert "google.com" not in data["highest_risk_url"] or \
                   data["highest_risk_level"] in ("Safe", "Low Risk")

    def test_highest_risk_level_is_valid(self):
        data = bulk_json(["https://google.com", "https://github.com"])
        if data.get("highest_risk_level"):
            assert data["highest_risk_level"] in (
                "Safe", "Low Risk", "Medium Risk", "High Risk"
            )

    def test_highest_risk_matches_max_of_results(self):
        data = bulk_json(["https://google.com", "https://microsoft.com"])
        completed = [r for r in data["results"] if r["status"] == "complete"]
        if not completed or not data.get("highest_risk_level"):
            pytest.skip("No completed results to compare")

        max_risk_in_results = max(
            completed,
            key=lambda r: self.RISK_ORDER.get(r.get("risk_level", "Safe"), 0)
        )
        assert data["highest_risk_level"] == max_risk_in_results["risk_level"]
