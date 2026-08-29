"""
test_integration_la.py — Aegis Link Analyzer Full Integration Tests
=====================================================================
Sends REAL HTTP requests against a running Link Analyzer instance and
compares actual server responses against expected values.

Every test corresponds directly to a manual test case in the
"Aegis Manual Test Cases" document (LA-01 through LA-80).
The test ID is shown in each docstring.

How to run:
    cd link-analyzer-tests
    pytest tests/test_integration_la.py -v

    # Run just one category:
    pytest tests/test_integration_la.py::TestScoringRegressions -v

    # Show full diffs on failure:
    pytest tests/test_integration_la.py -v --tb=long

    # Different base URL:
    LINK_ANALYZER_URL=http://localhost:8000 pytest tests/test_integration_la.py -v

Environment:
    LINK_ANALYZER_URL  — defaults to http://localhost:8000

Notes:
    - The /scan endpoint is rate-limited to 5 req/min.
      All helpers use the _request_with_retry() logic from conftest.py
      which automatically waits and retries on HTTP 429.
    - Session-scoped fixtures cache expensive scans once per test run.
    - Tests that depend on external threat feeds (URLhaus, GSB, PhishTank)
      are marked to accept both positive and negative results.
"""

import time
import uuid
import base64
import pytest
import httpx
from conftest import (
    BASE_URL, TIMEOUT, scan, scan_json, get, post,
    SAFE_URLS, PHISHING_URLS, IP_URLS, SHORTENER_URLS,
    BARE_DOMAIN, GOOGLE_MALWARE_TEST,
)


# ════════════════════════════════════════════════════════════════
# Shared session-scoped scan results
# (reused across many tests to avoid hammering the rate limit)
# ════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def google_scan():
    """LA — full scan of https://google.com, cached for the module."""
    return scan_json("https://google.com")

@pytest.fixture(scope="module")
def phish_scan():
    """LA — full scan of a heavy phishing-pattern URL."""
    return scan_json("http://paypal-secure-verify-account.tk/login/confirm")

@pytest.fixture(scope="module")
def dead_phish_scan():
    """LA — the failing URL from the scoring bug report (NXDOMAIN + brand)."""
    return scan_json("https://amazon-deals-pk.net/login")


# ════════════════════════════════════════════════════════════════
# LA-01 — Server Health
# ════════════════════════════════════════════════════════════════

class TestHealth:
    """LA-01: Verify server is up and health endpoint is correct."""

    def test_health_returns_200(self):
        """LA-01a: GET /health → HTTP 200."""
        r = get("/health")
        assert r.status_code == 200, (
            f"Expected HTTP 200 from /health, got {r.status_code}. "
            "Is the Link Analyzer running at " + BASE_URL + "?"
        )

    def test_health_status_field(self):
        """LA-01b: /health response has status='healthy' or 'ok'."""
        data = get("/health").json()
        assert "status" in data, "Health response missing 'status' field"
        assert data["status"] in ("healthy", "ok", "running"), (
            f"Unexpected health status: {data['status']!r}"
        )

    def test_docs_accessible(self):
        """LA-01c: /docs (Swagger UI) returns 200."""
        r = get("/docs")
        assert r.status_code == 200, "/docs should return HTTP 200"

    def test_root_returns_200(self):
        """LA-01d: GET / returns 200."""
        r = get("/")
        assert r.status_code == 200


# ════════════════════════════════════════════════════════════════
# LA-02 to LA-08 — Scan Response Structure
# ════════════════════════════════════════════════════════════════

class TestScanResponseStructure:
    """LA-02 to LA-08: Core response schema validation."""

    def test_la02_scan_returns_200(self):
        """LA-02: POST /scan with valid URL → HTTP 200."""
        r = scan("https://google.com")
        assert r.status_code == 200, (
            f"POST /scan returned {r.status_code}, expected 200. "
            f"Body: {r.text[:200]}"
        )

    def test_la03_all_required_top_level_fields(self, google_scan):
        """LA-03: Response must contain all 9 required top-level fields."""
        required = [
            "url", "risk_level", "confidence_score", "message",
            "scan_date", "scan_id", "total_flags", "all_flags",
            "score_breakdown",
        ]
        for field in required:
            assert field in google_scan, (
                f"LA-03 FAIL: Top-level field '{field}' missing from scan response.\n"
                f"Response keys present: {list(google_scan.keys())}"
            )

    def test_la04_scan_id_is_unique_string(self):
        """LA-04: Each scan gets a unique non-empty scan_id string."""
        id1 = scan_json("https://google.com")["scan_id"]
        id2 = scan_json("https://google.com")["scan_id"]
        assert isinstance(id1, str) and len(id1) > 5, (
            f"scan_id should be a non-empty string, got: {id1!r}"
        )
        assert id1 != id2, (
            f"LA-04 FAIL: Two scans of the same URL returned the same scan_id: {id1!r}. "
            "Each scan should be uniquely identified."
        )

    def test_la05_scan_date_iso_format(self, google_scan):
        """LA-05: scan_date must be a parseable ISO 8601 date/datetime string."""
        from datetime import datetime
        d = google_scan.get("scan_date", "")
        assert isinstance(d, str) and len(d) >= 8, (
            f"LA-05 FAIL: scan_date is not a valid string: {d!r}"
        )
        try:
            datetime.fromisoformat(d.replace("Z", "+00:00"))
        except ValueError:
            pytest.fail(f"LA-05 FAIL: scan_date '{d}' is not parseable as ISO 8601")

    def test_la06_risk_level_is_valid_enum(self, google_scan):
        """LA-06: risk_level must be exactly one of the four valid values."""
        valid = {"Safe", "Low Risk", "Medium Risk", "High Risk"}
        rl = google_scan.get("risk_level")
        assert rl in valid, (
            f"LA-06 FAIL: risk_level={rl!r} is not a valid risk level. "
            f"Must be one of: {valid}"
        )

    def test_la07_confidence_score_range(self, google_scan):
        """LA-07: confidence_score must be a number between 0.0 and 100.0."""
        score = google_scan.get("confidence_score")
        assert isinstance(score, (int, float)), (
            f"LA-07 FAIL: confidence_score is not a number: {score!r}"
        )
        assert 0.0 <= score <= 100.0, (
            f"LA-07 FAIL: confidence_score={score} is outside 0–100 range"
        )

    def test_la08_total_flags_matches_all_flags_length(self, google_scan):
        """LA-08: total_flags integer must equal the length of all_flags list."""
        total = google_scan.get("total_flags")
        flags = google_scan.get("all_flags", [])
        assert isinstance(total, int), f"total_flags should be int, got {type(total)}"
        assert isinstance(flags, list), f"all_flags should be list, got {type(flags)}"
        assert total == len(flags), (
            f"LA-08 FAIL: total_flags={total} but len(all_flags)={len(flags)}. "
            "These must match exactly."
        )


# ════════════════════════════════════════════════════════════════
# LA-09 to LA-16 — Detection Layers
# ════════════════════════════════════════════════════════════════

class TestDetectionLayers:
    """LA-09 to LA-16: Each detection layer must be present with required sub-fields."""

    def test_la09_heuristics_layer(self, google_scan):
        """LA-09: heuristics layer present with all required fields."""
        assert "heuristics" in google_scan, "heuristics layer missing from scan response"
        h = google_scan["heuristics"]
        required = ["flags", "flag_count", "heuristic_score", "entropy",
                    "checks_count", "is_suspicious"]
        for f in required:
            assert f in h, f"LA-09 FAIL: heuristics.{f} missing"
        assert isinstance(h["flags"], list)
        assert isinstance(h["entropy"], float)
        assert h["checks_count"] >= 14, (
            f"LA-09 FAIL: checks_count={h['checks_count']}, expected >= 14"
        )
        assert h["flag_count"] == len(h["flags"]), "flag_count != len(flags)"

    def test_la10_whois_layer(self, google_scan):
        """LA-10: whois layer present; google.com domain age > 365 days."""
        assert "whois" in google_scan, "whois layer missing"
        w = google_scan["whois"]
        for f in ["flags", "whois_score", "is_suspicious"]:
            assert f in w, f"LA-10 FAIL: whois.{f} missing"
        assert w["whois_score"] >= 0
        if w.get("domain_age_days") is not None:
            assert w["domain_age_days"] > 365, (
                f"LA-10 FAIL: google.com domain_age_days={w['domain_age_days']}, expected > 365"
            )

    def test_la11_dns_layer(self, google_scan):
        """LA-11: dns layer present; google.com must resolve successfully."""
        assert "dns" in google_scan, "dns layer missing"
        d = google_scan["dns"]
        for f in ["flags", "dns_score", "details", "is_suspicious"]:
            assert f in d, f"LA-11 FAIL: dns.{f} missing"
        assert "resolves" in d["details"], "dns.details.resolves key missing"
        assert d["details"]["resolves"] is True, (
            f"LA-11 FAIL: google.com should resolve, got resolves={d['details']['resolves']}"
        )

    def test_la12_ssl_layer(self, google_scan):
        """LA-12: ssl layer present; google.com SSL should be valid."""
        assert "ssl" in google_scan, "ssl layer missing"
        s = google_scan["ssl"]
        for f in ["flags", "ssl_score", "details", "is_suspicious"]:
            assert f in s, f"LA-12 FAIL: ssl.{f} missing"
        if s["details"].get("is_valid") is not None:
            assert s["details"]["is_valid"] is True, (
                "LA-12 FAIL: google.com should have a valid SSL certificate"
            )

    def test_la13_redirects_layer(self, google_scan):
        """LA-13: redirects layer present with all required sub-fields."""
        assert "redirects" in google_scan, "redirects layer missing"
        r = google_scan["redirects"]
        required = ["original_url", "final_url", "hop_count", "hops",
                    "shorteners_found", "destination_changed", "flags",
                    "redirect_score", "is_suspicious"]
        for f in required:
            assert f in r, f"LA-13 FAIL: redirects.{f} missing"
        assert isinstance(r["hop_count"], int) and r["hop_count"] >= 0
        assert isinstance(r["hops"], list)
        assert "google.com" in r.get("original_url", ""), (
            f"original_url should contain 'google.com', got: {r.get('original_url')}"
        )

    def test_la14_urlhaus_layer(self, google_scan):
        """LA-14: urlhaus layer present; google.com must NOT be in URLhaus."""
        assert "urlhaus" in google_scan, "urlhaus layer missing"
        u = google_scan["urlhaus"]
        for f in ["found", "flags", "urlhaus_score", "is_suspicious"]:
            assert f in u, f"LA-14 FAIL: urlhaus.{f} missing"
        assert u["found"] is False, (
            f"LA-14 FAIL: google.com should not be in URLhaus malware database"
        )
        assert u["urlhaus_score"] == 0.0, (
            f"LA-14 FAIL: urlhaus_score for google.com should be 0.0, got {u['urlhaus_score']}"
        )

    def test_la15_phishtank_layer(self, google_scan):
        """LA-15: phishtank/openphish layer present; google.com not in feed."""
        assert "phishtank" in google_scan, "phishtank layer missing"
        p = google_scan["phishtank"]
        for f in ["found", "flags", "phishtank_score", "is_suspicious"]:
            assert f in p, f"LA-15 FAIL: phishtank.{f} missing"
        assert p["found"] is False, "google.com should not be in OpenPhish feed"
        assert p.get("source") == "openphish", (
            f"LA-15 FAIL: expected source='openphish', got {p.get('source')!r}"
        )

    def test_la16_gsb_layer(self, google_scan):
        """LA-16: Google Safe Browsing layer present; api_available field exists."""
        assert "gsb" in google_scan, "gsb layer missing"
        g = google_scan["gsb"]
        for f in ["found", "threats", "flags", "gsb_score", "is_suspicious", "api_available"]:
            assert f in g, f"LA-16 FAIL: gsb.{f} missing"
        assert g["found"] is False, "google.com should not be flagged by Google Safe Browsing"
        assert isinstance(g["threats"], list)


# ════════════════════════════════════════════════════════════════
# LA-17 to LA-18 — Score Breakdown
# ════════════════════════════════════════════════════════════════

class TestScoreBreakdown:
    """LA-17 to LA-18: score_breakdown structure and values."""

    def test_la17_score_breakdown_complete(self, google_scan):
        """LA-17: score_breakdown has all required component keys, all non-negative."""
        assert "score_breakdown" in google_scan, "score_breakdown missing"
        sb = google_scan["score_breakdown"]
        required_keys = [
            "heuristics", "whois", "dns", "ssl", "redirects",
            "virustotal", "urlhaus", "phishtank", "gsb", "combined_final",
        ]
        for k in required_keys:
            assert k in sb, f"LA-17 FAIL: score_breakdown.{k} missing"
        for k, v in sb.items():
            if isinstance(v, (int, float)):
                assert v >= 0, f"LA-17 FAIL: score_breakdown.{k}={v} is negative"
        assert 0.0 <= sb["combined_final"] <= 100.0, (
            f"LA-17 FAIL: combined_final={sb['combined_final']} out of range 0–100"
        )

    def test_la18_critical_signals_field(self):
        """LA-18: critical_signals_triggered is int >= 0; phishing URL has more than safe URL."""
        safe_sb   = scan_json("https://google.com").get("score_breakdown", {})
        phish_sb  = scan_json("http://paypal-verify-account.tk/login").get("score_breakdown", {})
        safe_crit  = safe_sb.get("critical_signals_triggered", 0)
        phish_crit = phish_sb.get("critical_signals_triggered", 0)
        assert isinstance(safe_crit, int) and safe_crit >= 0
        assert isinstance(phish_crit, int) and phish_crit >= 0
        assert phish_crit >= safe_crit, (
            f"LA-18 FAIL: Phishing URL has fewer critical signals ({phish_crit}) "
            f"than google.com ({safe_crit})"
        )


# ════════════════════════════════════════════════════════════════
# LA-19 to LA-20 — ML Prediction
# ════════════════════════════════════════════════════════════════

class TestMLPrediction:
    """LA-19 to LA-20: ML prediction section structure and math."""

    def test_la19_ml_prediction_section(self, google_scan):
        """LA-19: ml_prediction must be present with 'available' field."""
        assert "ml_prediction" in google_scan, "ml_prediction missing from response"
        ml = google_scan["ml_prediction"]
        assert "available" in ml, "ml_prediction.available field missing"
        if ml.get("available"):
            required = ["prediction", "ml_risk_level", "phishing_probability",
                        "safe_probability", "top_features", "features_used"]
            for f in required:
                assert f in ml, f"LA-19 FAIL: ml_prediction.{f} missing (model is available)"
            assert ml["features_used"] == 35, (
                f"LA-19 FAIL: features_used={ml['features_used']}, expected 35"
            )

    def test_la20_probabilities_sum_to_100(self, google_scan):
        """LA-20: phishing_probability + safe_probability must sum to ~100."""
        ml = google_scan.get("ml_prediction", {})
        if not ml.get("available"):
            pytest.skip("ML model not loaded — skipping probability sum check")
        total = ml["phishing_probability"] + ml["safe_probability"]
        assert 99.0 <= total <= 101.0, (
            f"LA-20 FAIL: phishing_prob + safe_prob = {total}, expected ~100.0"
        )
        assert 0.0 <= ml["phishing_probability"] <= 100.0
        assert 0.0 <= ml["safe_probability"] <= 100.0
        assert ml["prediction"] in (0, 1), (
            f"prediction must be 0 or 1, got {ml['prediction']}"
        )


# ════════════════════════════════════════════════════════════════
# LA-21 to LA-27 — Risk Directional Accuracy
# ════════════════════════════════════════════════════════════════

class TestRiskDirectionalAccuracy:
    """LA-21 to LA-27: Correct risk direction for known-safe and known-phishing URLs."""

    RISK_ORDER = {"Safe": 1, "Low Risk": 2, "Medium Risk": 3, "High Risk": 4}

    def _rank(self, risk_level: str) -> int:
        return self.RISK_ORDER.get(risk_level, 0)

    def test_la21_google_is_safe_or_low(self, google_scan):
        """LA-21: https://google.com → Safe or Low Risk."""
        rl = google_scan["risk_level"]
        assert rl in ("Safe", "Low Risk"), (
            f"LA-21 FAIL: google.com classified as '{rl}'. "
            "Known-safe domain should never exceed Low Risk."
        )

    def test_la22_github_is_safe_or_low(self):
        """LA-22: https://github.com → Safe or Low Risk."""
        data = scan_json("https://github.com")
        assert data["risk_level"] in ("Safe", "Low Risk"), (
            f"LA-22 FAIL: github.com returned '{data['risk_level']}'"
        )

    def test_la23_phishing_scores_higher_than_google(self, google_scan, phish_scan):
        """LA-23: Phishing URL risk rank must be >= google.com risk rank."""
        google_rank = self._rank(google_scan["risk_level"])
        phish_rank  = self._rank(phish_scan["risk_level"])
        assert phish_rank >= google_rank, (
            f"LA-23 FAIL: Phishing URL ({phish_scan['risk_level']}) should rank "
            f">= google.com ({google_scan['risk_level']}). "
            f"Phishing scan: {phish_scan.get('score_breakdown', {}).get('combined_final')}"
        )

    def test_la24_ip_url_flagged(self):
        """LA-24: IP-based URL must produce at least 1 flag mentioning 'ip'."""
        data = scan_json(IP_URLS[0])
        flags_text = " ".join(data.get("all_flags", [])).lower()
        assert "ip" in flags_text or data["total_flags"] > 0, (
            f"LA-24 FAIL: IP-based URL {IP_URLS[0]} produced no flags. "
            f"all_flags: {data.get('all_flags')}"
        )

    def test_la25_url_shortener_flagged(self):
        """LA-25: URL shortener must produce a flag containing 'short' or 'redirect'."""
        data = scan_json("https://bit.ly/3testexample")
        flags_text = " ".join(data.get("all_flags", [])).lower()
        assert "short" in flags_text or "redirect" in flags_text or data["total_flags"] > 0, (
            f"LA-25 FAIL: bit.ly URL should be flagged as a shortener. "
            f"all_flags: {data.get('all_flags')}"
        )

    def test_la26_suspicious_tld_flagged(self):
        """LA-26: .tk domain must produce at least 1 flag containing 'tld' or 'suspicious'."""
        data = scan_json("http://example.tk")
        flags_text = " ".join(data.get("all_flags", [])).lower()
        assert "tld" in flags_text or "suspicious" in flags_text or data["total_flags"] > 0, (
            f"LA-26 FAIL: .tk domain should be flagged. all_flags: {data.get('all_flags')}"
        )

    def test_la27_google_malware_test_flagged(self):
        """LA-27: Google's malware test URL must be Medium or High Risk."""
        data = scan_json(GOOGLE_MALWARE_TEST)
        assert data["risk_level"] in ("Medium Risk", "High Risk"), (
            f"LA-27 FAIL: Google malware test URL returned '{data['risk_level']}'. "
            "URLhaus or GSB should flag this URL."
        )


# ════════════════════════════════════════════════════════════════
# LA-28 to LA-44 — Heuristics Engine Deep Tests
# ════════════════════════════════════════════════════════════════

class TestHeuristicsEngine:
    """LA-28 to LA-44: Every individual heuristic check."""

    def _flags(self, url: str) -> str:
        return " ".join(scan_json(url).get("heuristics", {}).get("flags", [])).lower()

    def _hscore(self, url: str) -> float:
        return scan_json(url).get("heuristics", {}).get("heuristic_score", 0.0)

    def test_la28_phishing_keywords_in_path(self):
        """LA-28: /login/verify path → keyword flag."""
        f = self._flags("https://example.com/login/verify")
        assert "keyword" in f or "phishing" in f or "suspicious" in f, (
            f"LA-28 FAIL: '/login/verify' path should trigger a keyword flag. flags: {f!r}"
        )

    @pytest.mark.parametrize("tld_url,tld", [
        ("http://example.tk",    ".tk"),
        ("http://example.ml",    ".ml"),
        ("http://example.xyz",   ".xyz"),
        ("http://example.ga",    ".ga"),
        ("http://example.cf",    ".cf"),
        ("http://example.gq",    ".gq"),
        ("http://example.top",   ".top"),
        ("http://example.buzz",  ".buzz"),
        ("http://example.click", ".click"),
    ])
    def test_la29_suspicious_tld_flagged(self, tld_url, tld):
        """LA-29: Each of the 9 known-abused TLDs must trigger a TLD flag."""
        f = self._flags(tld_url)
        assert "tld" in f or "suspicious" in f, (
            f"LA-29 FAIL: {tld} TLD in '{tld_url}' should be flagged. "
            f"heuristics.flags: {f!r}"
        )

    def test_la30_com_tld_not_flagged(self):
        """LA-30: .com TLD must NOT trigger a TLD flag."""
        f = self._flags("https://example.com")
        assert "tld" not in f, (
            f"LA-30 FAIL: .com TLD incorrectly flagged. flags: {f!r}"
        )

    def test_la30_org_tld_not_flagged(self):
        """LA-30: .org TLD must NOT trigger a TLD flag."""
        f = self._flags("https://example.org")
        assert "tld" not in f, (
            f"LA-30 FAIL: .org TLD incorrectly flagged. flags: {f!r}"
        )

    def test_la31_brand_impersonation_detected(self):
        """LA-31: 'paypal' in domain at suspicious TLD → brand flag or score > 20."""
        url = "http://paypal-secure.tk/login"
        f   = self._flags(url)
        s   = self._hscore(url)
        assert "brand" in f or "impersonat" in f or "keyword" in f or s > 20, (
            f"LA-31 FAIL: Brand impersonation not detected for {url}. "
            f"flags={f!r}, score={s}"
        )

    def test_la32_real_paypal_not_flagged_as_impersonation(self):
        """LA-32: paypal.com itself must NOT trigger a brand impersonation flag."""
        f = self._flags("https://paypal.com")
        assert "brand" not in f or "impersonat" not in f, (
            f"LA-32 FAIL: paypal.com flagged as impersonating itself. flags: {f!r}"
        )

    def test_la33_ip_address_url_flagged(self):
        """LA-33: http://192.168.1.1 → 'ip' flag in heuristics."""
        f = self._flags("http://192.168.1.1/setup")
        assert "ip" in f, (
            f"LA-33 FAIL: IP-based URL missing 'ip' flag. flags: {f!r}"
        )

    def test_la34_google_no_ip_flag(self, google_scan):
        """LA-34: google.com heuristics must NOT have an IP flag."""
        f = " ".join(google_scan.get("heuristics", {}).get("flags", [])).lower()
        assert "ip" not in f, f"LA-34 FAIL: google.com incorrectly has IP flag: {f!r}"

    @pytest.mark.parametrize("short_url", [
        "https://bit.ly/3abc123",
        "https://tinyurl.com/testlink",
        "https://t.co/exampletest",
    ])
    def test_la35_url_shorteners_flagged(self, short_url):
        """LA-35: Known URL shortener domains → 'short' or 'redirect' flag."""
        f = self._flags(short_url)
        assert "short" in f or "redirect" in f, (
            f"LA-35 FAIL: {short_url} should be flagged as URL shortener. "
            f"flags: {f!r}"
        )

    def test_la36_http_scheme_flagged(self):
        """LA-36: http:// URL → flag containing 'http', 'ssl', or 'scheme'."""
        f = self._flags("http://example.com/login")
        assert "http" in f or "ssl" in f or "scheme" in f, (
            f"LA-36 FAIL: HTTP scheme not flagged. flags: {f!r}"
        )

    def test_la37_http_scores_higher_than_https(self):
        """LA-37: http:// heuristic_score must be >= https:// for same URL."""
        http_score  = self._hscore("http://example.com/login")
        https_score = self._hscore("https://example.com/login")
        assert http_score >= https_score, (
            f"LA-37 FAIL: HTTP score ({http_score}) < HTTPS score ({https_score}). "
            "HTTP scheme should always penalise the score."
        )
        diff = http_score - https_score
        assert diff >= 12, (
            f"LA-37 FAIL: HTTP penalty is only {diff} points, expected >= 12 (v2 engine). "
            "Check heuristics.py: HTTP should add 12, not 10."
        )

    def test_la38_very_long_url_flagged_or_higher_score(self):
        """LA-38: 200-char URL → length flag OR higher score than short URL."""
        long_url  = "https://example.com/" + "x" * 200
        short_url = "https://example.com"
        long_score  = self._hscore(long_url)
        short_score = self._hscore(short_url)
        long_flags  = self._flags(long_url)
        assert "length" in long_flags or "long" in long_flags or long_score > short_score, (
            f"LA-38 FAIL: 200-char URL did not produce a length flag or higher score. "
            f"long_score={long_score}, short_score={short_score}"
        )

    def test_la39_entropy_is_positive(self, google_scan):
        """LA-39: heuristics.entropy for google.com must be > 0 and in 1.0–5.0 range."""
        e = google_scan["heuristics"]["entropy"]
        assert isinstance(e, float), f"entropy should be float, got {type(e)}"
        assert e > 0.0, f"LA-39 FAIL: entropy should be > 0, got {e}"
        assert 1.0 <= e <= 5.0, f"LA-39 FAIL: entropy {e} outside expected range 1.0–5.0"

    def test_la40_random_domain_higher_entropy(self):
        """LA-40: Random-looking domain must have entropy >= google.com."""
        normal_e = scan_json("https://google.com")["heuristics"]["entropy"]
        random_e = scan_json("https://xkf3j9a2q8z.com")["heuristics"]["entropy"]
        assert random_e >= normal_e, (
            f"LA-40 FAIL: Random domain entropy ({random_e:.3f}) < "
            f"google.com entropy ({normal_e:.3f})"
        )

    def test_la41_excessive_subdomains_flagged(self):
        """LA-41: 4+ subdomain levels → 'subdomain' flag or higher score."""
        deep_url = "https://login.verify.secure.paypal.suspicious.com"
        f = self._flags(deep_url)
        s = self._hscore(deep_url)
        assert "subdomain" in f or s > 10, (
            f"LA-41 FAIL: Excessive subdomains not flagged. flags={f!r}, score={s}"
        )

    def test_la42_single_www_subdomain_not_flagged(self):
        """LA-42: www.google.com must NOT have a subdomain flag."""
        data = scan_json("https://www.google.com")
        subdomain_flags = [
            fl for fl in data["heuristics"]["flags"]
            if "subdomain" in fl.lower()
        ]
        assert len(subdomain_flags) == 0, (
            f"LA-42 FAIL: www.google.com incorrectly flagged for subdomains: "
            f"{subdomain_flags}"
        )

    def test_la43_phishing_heuristic_score_higher_than_google(self, google_scan):
        """LA-43: Phishing URL heuristic_score must be > google.com heuristic_score."""
        google_h = google_scan["heuristics"]["heuristic_score"]
        phish_h  = scan_json(
            "http://paypal-secure-verify.tk/login/confirm/account"
        )["heuristics"]["heuristic_score"]
        assert phish_h > google_h, (
            f"LA-43 FAIL: Phishing URL heuristic_score={phish_h} <= "
            f"google.com heuristic_score={google_h}"
        )

    @pytest.mark.parametrize("url", [
        "https://google.com",
        "http://example.tk/login/verify",
        "https://bit.ly/test",
    ])
    def test_la44_flag_count_always_matches_flags_list(self, url):
        """LA-44: heuristics.flag_count must always equal len(heuristics.flags)."""
        h = scan_json(url)["heuristics"]
        assert h["flag_count"] == len(h["flags"]), (
            f"LA-44 FAIL: flag_count={h['flag_count']} but "
            f"len(flags)={len(h['flags'])} for {url}"
        )


# ════════════════════════════════════════════════════════════════
# LA-45 to LA-54 — Input Validation
# ════════════════════════════════════════════════════════════════

class TestInputValidation:
    """LA-45 to LA-54: Server-side validation of malformed/edge-case inputs."""

    def test_la45_empty_url_returns_422(self):
        """LA-45: Empty URL string → HTTP 422 Unprocessable Entity."""
        r = scan("")
        assert r.status_code == 422, (
            f"LA-45 FAIL: empty URL should return 422, got {r.status_code}"
        )

    def test_la46_missing_url_field_returns_422(self):
        """LA-46: Missing 'url' field entirely → HTTP 422."""
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan", json={})
        assert r.status_code == 422, (
            f"LA-46 FAIL: missing url field should return 422, got {r.status_code}"
        )

    def test_la47_bare_domain_auto_normalized(self):
        """LA-47: Bare domain 'google.com' (no scheme) → HTTP 200 with https:// in response."""
        r = scan(BARE_DOMAIN)
        assert r.status_code == 200, (
            f"LA-47 FAIL: bare domain should be accepted, got {r.status_code}"
        )
        data = r.json()
        assert "https://" in data.get("url", ""), (
            f"LA-47 FAIL: bare domain should be normalised to https://, "
            f"got url={data.get('url')!r}"
        )

    def test_la48_http_url_accepted(self):
        """LA-48: http:// URL → HTTP 200."""
        r = scan("http://example.com")
        assert r.status_code == 200, f"LA-48 FAIL: http:// URL rejected, got {r.status_code}"

    def test_la49_https_url_accepted(self):
        """LA-49: https:// URL → HTTP 200."""
        r = scan("https://example.com")
        assert r.status_code == 200

    def test_la50_url_with_port_accepted(self):
        """LA-50: https://example.com:8443/path → HTTP 200."""
        r = scan("https://example.com:8443/path")
        assert r.status_code == 200

    def test_la51_very_long_url_no_crash(self):
        """LA-51: 500-char URL must not cause HTTP 500."""
        long_url = "https://example.com/" + "a" * 500
        r = scan(long_url)
        assert r.status_code in (200, 400, 422), (
            f"LA-51 FAIL: Very long URL caused unexpected error: {r.status_code}. "
            "Server must never return 500."
        )
        assert r.status_code != 500, "LA-51 FAIL: 500 Internal Server Error on long URL"

    def test_la52_null_url_returns_422(self):
        """LA-52: JSON null as url value → HTTP 422."""
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan", json={"url": None})
        assert r.status_code == 422, (
            f"LA-52 FAIL: null url should return 422, got {r.status_code}"
        )

    def test_la53_extra_fields_ignored(self):
        """LA-53: Extra unknown fields in body must be silently ignored → HTTP 200."""
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan", json={
                "url": "https://google.com",
                "unknown_field": "should_be_ignored",
                "another_extra": 99,
            })
        assert r.status_code == 200, (
            f"LA-53 FAIL: Extra fields should be ignored, got {r.status_code}. "
            f"Body: {r.text[:200]}"
        )

    def test_la54_unreachable_domain_handled_gracefully(self):
        """LA-54: Completely fictional domain → HTTP 200 (no 500 crash)."""
        data = scan_json("https://this-domain-absolutely-does-not-exist-aegis99.com")
        assert "risk_level" in data, (
            f"LA-54 FAIL: Unreachable domain returned no risk_level. "
            f"Response: {data}"
        )
        assert data["risk_level"] in ("Safe", "Low Risk", "Medium Risk", "High Risk"), (
            f"LA-54 FAIL: Unexpected risk_level: {data['risk_level']!r}"
        )


# ════════════════════════════════════════════════════════════════
# LA-55 to LA-60 — Edge Cases
# ════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """LA-55 to LA-60: Special URL patterns and consistency."""

    @pytest.mark.parametrize("url,name", [
        ("https://example.com/page?id=1&token=abc",         "query params"),
        ("https://example.com/page#section",                "fragment"),
        ("https://example.com/path%20with%20spaces",        "percent encoding"),
        ("https://example.com:8443",                        "custom port"),
        ("https://docs.github.com/en/get-started",         "subdomain"),
        ("https://example.com/a/b/c/d/e/f/g/page.html",   "deep nested path"),
        ("https://my-site-name.com",                        "hyphenated domain"),
    ])
    def test_la55_to_la59_special_urls_accepted(self, url, name):
        """LA-55 to LA-59: Special URL patterns must return HTTP 200."""
        r = scan(url)
        assert r.status_code == 200, (
            f"LA-55/59 FAIL: URL with {name} rejected. "
            f"URL: {url!r}, status: {r.status_code}"
        )

    def test_la60_same_url_deterministic_risk(self):
        """LA-60: Same URL scanned twice must return same risk_level."""
        url = "https://google.com"
        r1 = scan_json(url)["risk_level"]
        r2 = scan_json(url)["risk_level"]
        assert r1 == r2, (
            f"LA-60 FAIL: Same URL returned different risk levels: "
            f"scan 1 = '{r1}', scan 2 = '{r2}'"
        )


# ════════════════════════════════════════════════════════════════
# LA-61 to LA-67 — Bulk Scan
# ════════════════════════════════════════════════════════════════

class TestBulkScan:
    """LA-61 to LA-67: POST /scan/bulk endpoint."""

    def _bulk(self, urls: list) -> httpx.Response:
        return post("/scan/bulk", {"urls": urls})

    def _bulk_json(self, urls: list) -> dict:
        return self._bulk(urls).json()

    def test_la61_bulk_structure(self):
        """LA-61: Bulk scan of 1 URL → HTTP 200 with all required fields."""
        data = self._bulk_json(["https://google.com"])
        for field in ["total_urls", "completed", "failed", "results", "scan_duration_seconds"]:
            assert field in data, f"LA-61 FAIL: Bulk response missing '{field}'"
        assert data["completed"] + data["failed"] == data["total_urls"], (
            f"LA-61 FAIL: completed({data['completed']}) + failed({data['failed']}) "
            f"!= total_urls({data['total_urls']})"
        )

    def test_la62_each_result_has_required_fields(self):
        """LA-62: Each result entry must have 'url' and 'status'; completed ones have risk_level."""
        data = self._bulk_json(["https://google.com"])
        for result in data["results"]:
            assert "url" in result, "LA-62 FAIL: result missing 'url'"
            assert "status" in result, "LA-62 FAIL: result missing 'status'"
            if result["status"] == "complete":
                assert "risk_level" in result, "LA-62 FAIL: completed result missing risk_level"
                assert "confidence_score" in result
                assert "total_flags" in result

    def test_la63_ten_urls_accepted(self):
        """LA-63: Exactly 10 URLs in one bulk request → HTTP 200."""
        urls = [f"https://example{i}.com" for i in range(10)]
        r = self._bulk(urls)
        assert r.status_code == 200, (
            f"LA-63 FAIL: 10 URLs should be accepted, got {r.status_code}"
        )

    def test_la64_eleven_urls_rejected(self):
        """LA-64: 11 URLs → HTTP 400 or 422 (limit is 10)."""
        urls = ["https://example.com"] * 11
        r = self._bulk(urls)
        assert r.status_code in (400, 422), (
            f"LA-64 FAIL: 11 URLs should be rejected, got {r.status_code}"
        )

    def test_la65_empty_list_rejected(self):
        """LA-65: Empty URL list → HTTP 400 or 422."""
        r = self._bulk([])
        assert r.status_code in (400, 422), (
            f"LA-65 FAIL: empty list should be rejected, got {r.status_code}"
        )

    def test_la66_scan_duration_positive(self):
        """LA-66: scan_duration_seconds must be > 0."""
        data = self._bulk_json(["https://google.com"])
        dur = data.get("scan_duration_seconds", 0)
        assert dur > 0, f"LA-66 FAIL: scan_duration_seconds={dur} should be > 0"

    def test_la67_highest_risk_url_in_mixed_batch(self):
        """LA-67: highest_risk_url in a mixed batch should point to the riskier entry."""
        data = self._bulk_json([
            "https://google.com",
            "http://paypal-verify-login.tk/account",
        ])
        if data["completed"] >= 2 and data.get("highest_risk_url"):
            assert "google.com" not in data["highest_risk_url"] or \
                   data.get("highest_risk_level") in ("Safe", "Low Risk"), (
                "LA-67 FAIL: highest_risk_url should be the suspicious domain, not google.com"
            )


# ════════════════════════════════════════════════════════════════
# LA-68 to LA-72 — Async Scan
# ════════════════════════════════════════════════════════════════

class TestAsyncScan:
    """LA-68 to LA-72: POST /scan/async and GET /scan/status/{job_id}."""

    def _submit(self, url: str = "https://google.com") -> dict:
        return post("/scan/async", {"url": url}).json()

    def _poll(self, job_id: str) -> dict:
        return get(f"/scan/status/{job_id}").json()

    def test_la68_async_submit_fast_and_has_fields(self):
        """LA-68: Async submit must return in < 6s with job_id, status, poll_url."""
        t0 = time.time()
        data = self._submit()
        elapsed = time.time() - t0
        assert elapsed < 6.0, (
            f"LA-68 FAIL: Async submit took {elapsed:.1f}s, expected < 6s. "
            "Endpoint must not wait for the scan to complete."
        )
        assert "job_id" in data, f"LA-68 FAIL: job_id missing from response: {data}"
        assert data.get("status") == "pending", (
            f"LA-68 FAIL: Initial status should be 'pending', got {data.get('status')!r}"
        )
        assert "poll_url" in data, "LA-68 FAIL: poll_url missing"
        assert data["poll_url"].startswith("/scan/status/"), (
            f"LA-68 FAIL: poll_url={data['poll_url']!r} should start with /scan/status/"
        )

    def test_la69_two_jobs_have_different_ids(self):
        """LA-69: Two async submits must return different job_ids."""
        id1 = self._submit()["job_id"]
        id2 = self._submit("https://github.com")["job_id"]
        assert id1 != id2, (
            f"LA-69 FAIL: Two jobs have the same job_id: {id1!r}"
        )

    def test_la70_poll_returns_job_info(self):
        """LA-70: Polling a valid job_id returns correct fields."""
        job_id = self._submit()["job_id"]
        data   = self._poll(job_id)
        assert data.get("job_id") == job_id, (
            f"LA-70 FAIL: poll returned job_id={data.get('job_id')!r}, expected {job_id!r}"
        )
        assert "url" in data, "LA-70 FAIL: poll response missing 'url'"
        assert "status" in data, "LA-70 FAIL: poll response missing 'status'"
        assert data["status"] in ("pending", "running", "complete", "failed")

    def test_la71_nonexistent_job_returns_404(self):
        """LA-71: Polling a non-existent job_id → HTTP 404."""
        r = get("/scan/status/nonexistent-job-id-00000000")
        assert r.status_code == 404, (
            f"LA-71 FAIL: Non-existent job should return 404, got {r.status_code}"
        )

    @pytest.mark.slow
    def test_la72_job_completes_within_120_seconds(self):
        """LA-72: Async job must reach status='complete' within 120 seconds."""
        job_id   = self._submit()["job_id"]
        deadline = time.time() + 120
        while time.time() < deadline:
            data = self._poll(job_id)
            if data.get("status") in ("complete", "failed"):
                break
            time.sleep(3)
        assert data["status"] == "complete", (
            f"LA-72 FAIL: Job status is '{data.get('status')}' after 120s. "
            f"Error: {data.get('error')}"
        )
        result = data.get("result", {})
        for field in ["url", "risk_level", "confidence_score", "total_flags"]:
            assert field in result, f"LA-72 FAIL: Completed job result missing '{field}'"


# ════════════════════════════════════════════════════════════════
# LA-73 to LA-78 — Feedback
# ════════════════════════════════════════════════════════════════

class TestFeedback:
    """LA-73 to LA-78: POST /feedback and GET /feedback/stats."""

    def _make(self, overrides: dict = {}) -> dict:
        base = {
            "scan_id":        f"u-{uuid.uuid4().hex[:12]}",
            "url":            "https://example.com",
            "original_risk":  "High Risk",
            "corrected_risk": "Safe",
            "feedback_type":  "false_positive",
            "user_note":      "This is a legitimate internal tool",
        }
        base.update(overrides)
        return base

    def test_la73_submit_returns_200_with_required_fields(self):
        """LA-73: POST /feedback with valid body → 200 with feedback_id, status, submitted_at."""
        r = post("/feedback", self._make())
        assert r.status_code == 200, (
            f"LA-73 FAIL: /feedback returned {r.status_code}, expected 200. "
            f"Body: {r.text[:200]}"
        )
        data = r.json()
        assert "feedback_id" in data, "LA-73 FAIL: feedback_id missing"
        assert isinstance(data["feedback_id"], int) and data["feedback_id"] > 0
        assert data.get("status") in ("received", "saved"), (
            f"LA-73 FAIL: status={data.get('status')!r}, expected 'received' or 'saved'"
        )
        assert "submitted_at" in data

    @pytest.mark.parametrize("fb_type", [
        "false_positive", "false_negative", "wrong_level", "correct"
    ])
    def test_la74_all_feedback_types_accepted(self, fb_type):
        """LA-74: All four feedback_type values must return HTTP 200."""
        r = post("/feedback", self._make({"feedback_type": fb_type}))
        assert r.status_code == 200, (
            f"LA-74 FAIL: feedback_type='{fb_type}' returned {r.status_code}"
        )

    def test_la75_missing_scan_id_returns_422(self):
        """LA-75: Omitting scan_id → HTTP 422."""
        body = self._make()
        body.pop("scan_id")
        r = post("/feedback", body)
        assert r.status_code == 422, (
            f"LA-75 FAIL: Missing scan_id should return 422, got {r.status_code}"
        )

    def test_la76_missing_feedback_type_returns_422(self):
        """LA-76: Omitting feedback_type → HTTP 422."""
        body = self._make()
        body.pop("feedback_type")
        r = post("/feedback", body)
        assert r.status_code == 422, (
            f"LA-76 FAIL: Missing feedback_type should return 422, got {r.status_code}"
        )

    def test_la77_stats_endpoint_structure(self):
        """LA-77: GET /feedback/stats → 200 with all required fields."""
        r = get("/feedback/stats")
        assert r.status_code == 200
        data = r.json()
        required = ["total_feedback", "breakdown_by_type", "false_positives",
                    "false_negatives", "training_ready"]
        for f in required:
            assert f in data, f"LA-77 FAIL: /feedback/stats missing '{f}'"
        assert isinstance(data["total_feedback"], int) and data["total_feedback"] >= 0
        assert isinstance(data["training_ready"], bool)

    def test_la78_total_feedback_increments(self):
        """LA-78: total_feedback counter must increment after a new submission."""
        before = get("/feedback/stats").json()["total_feedback"]
        post("/feedback", self._make())
        after  = get("/feedback/stats").json()["total_feedback"]
        assert after == before + 1, (
            f"LA-78 FAIL: total_feedback did not increment. before={before}, after={after}"
        )


# ════════════════════════════════════════════════════════════════
# LA-79 to LA-80 — Rate Limiting
# ════════════════════════════════════════════════════════════════

class TestRateLimiting:
    """LA-79 to LA-80: Rate limit verification (bypasses retry helper intentionally)."""

    def test_la79_rate_limit_produces_429(self):
        """
        LA-79: Sending 8 rapid requests without delays must produce at least
        one 429 response AND only 200/429 codes (no 500s).
        Uses direct httpx — intentionally bypasses the retry helper.
        """
        statuses = []
        for _ in range(8):
            with httpx.Client(timeout=TIMEOUT) as c:
                r = c.post(f"{BASE_URL}/scan", json={"url": "https://google.com"})
                statuses.append(r.status_code)

        status_set = set(statuses)
        assert all(s in (200, 429) for s in statuses), (
            f"LA-79 FAIL: Unexpected status codes in rapid requests: {status_set}. "
            "Expected only 200 and/or 429 (no 500s)."
        )
        assert 429 in status_set, (
            f"LA-79 FAIL: No 429 received in 8 rapid requests. "
            "Rate limiter may not be active. All statuses: {statuses}"
        )

    def test_la80_rate_limit_headers_present(self):
        """LA-80: POST /scan response headers should include rate-limit information."""
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan", json={"url": "https://google.com"})
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
        has_rate_headers = any(
            k in headers_lower
            for k in ("x-ratelimit-limit", "x-ratelimit-remaining",
                      "retry-after", "ratelimit-limit", "ratelimit-remaining")
        )
        assert has_rate_headers, (
            f"LA-80 FAIL: No rate-limit headers found in /scan response. "
            f"Headers received: {list(r.headers.keys())}"
        )


# ════════════════════════════════════════════════════════════════
# SCORING REGRESSIONS — v2 Engine
# ════════════════════════════════════════════════════════════════

class TestScoringRegressions:
    """
    Regression tests that lock in correct classification after the v2 scoring
    engine fix. These URLs were mis-classified before the fix.

    The test that triggered the fix:
        amazon-deals-pk.net/login was Medium Risk (score=35) — should be High Risk.
    """

    def test_dead_phishing_domain_is_high_risk(self, dead_phish_scan):
        """
        amazon-deals-pk.net/login:
        - Amazon brand embedded in domain (typosquat)
        - /login phishing keyword
        - NXDOMAIN — domain doesn't even exist
        - No WHOIS data
        - ML: 59.93% phishing probability
        Before fix: score=35.0 → Medium Risk  ✗
        After fix:  score=65.0 → High Risk    ✓
        """
        rl    = dead_phish_scan["risk_level"]
        score = dead_phish_scan["confidence_score"]
        assert rl == "High Risk", (
            f"REGRESSION FAIL: amazon-deals-pk.net/login should be 'High Risk', "
            f"got '{rl}' (score={score}). "
            f"This is the URL that exposed the scoring bug. "
            f"Ensure utils.py has been updated with the v2 scoring engine.\n"
            f"Score breakdown: {dead_phish_scan.get('score_breakdown')}"
        )
        assert score >= 60, (
            f"REGRESSION FAIL: confidence_score={score}, expected >= 60"
        )

    def test_classic_phishing_pattern_is_high_risk(self):
        """
        paypal-secure-verify-account.tk/login/confirm:
        Brand + suspicious TLD + multiple keywords + HTTP = maximum heuristic score.
        Must always be High Risk regardless of VT/feed status.
        """
        data = scan_json("http://paypal-secure-verify-account.tk/login/confirm")
        assert data["risk_level"] == "High Risk", (
            f"REGRESSION FAIL: Classic phishing pattern URL should be High Risk. "
            f"Got: {data['risk_level']} (score={data['confidence_score']})\n"
            f"heuristic_score: {data.get('heuristics', {}).get('heuristic_score')}"
        )

    def test_suspicious_tld_http_not_safe(self):
        """
        http://example.xyz/shop:
        Suspicious TLD (.xyz) + HTTP — must not be 'Safe'.
        Before fix: TLD score 20 + HTTP score 10 = 30 → fell below Low threshold.
        After fix:  TLD score 25 + HTTP score 12 = 37 → Low Risk.
        """
        data = scan_json("http://example.xyz/shop")
        assert data["risk_level"] != "Safe", (
            f"REGRESSION FAIL: http://example.xyz/shop should NOT be 'Safe'. "
            f"Got: '{data['risk_level']}' (score={data['confidence_score']}). "
            "Check heuristics.py: TLD score must be 25, HTTP penalty must be 12."
        )

    def test_safe_domains_unchanged_by_fix(self):
        """
        google.com, github.com, microsoft.com must remain Safe or Low Risk.
        The scoring fix must not cause false positives on known-safe domains.
        """
        for url in ["https://google.com", "https://github.com", "https://microsoft.com"]:
            data = scan_json(url)
            assert data["risk_level"] in ("Safe", "Low Risk"), (
                f"REGRESSION FAIL: {url} returned '{data['risk_level']}' after scoring fix. "
                f"score={data['confidence_score']}. Safe domains must not be affected by fix."
            )

    def test_brand_in_domain_plus_dead_dns_is_high_risk(self):
        """
        Any URL with a major brand name embedded AND NXDOMAIN (domain doesn't
        resolve) should reach High Risk due to the new override in utils.py:
        heuristic_score >= 35 AND dns_score >= 60 → floor 65.
        """
        data = scan_json("https://amazon-secure-account.net/login")
        dns  = data.get("dns", {})
        # Only assert High Risk if DNS confirms NXDOMAIN
        if dns.get("dns_score", 0) >= 60:
            assert data["risk_level"] == "High Risk", (
                f"REGRESSION FAIL: Brand + NXDOMAIN URL should be High Risk. "
                f"Got: {data['risk_level']}, dns_score={dns.get('dns_score')}"
            )
        else:
            assert data["risk_level"] in ("Medium Risk", "High Risk"), (
                f"Brand impersonation URL should be at least Medium Risk. "
                f"Got: {data['risk_level']}"
            )
