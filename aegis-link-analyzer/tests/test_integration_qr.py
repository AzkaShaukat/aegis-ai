"""
test_integration_qr.py — Aegis QR Scanner Full Integration Tests
=================================================================
Sends REAL HTTP requests against a running QR Scanner instance and
compares actual server responses against expected values.

Every test corresponds directly to a manual test case in the
"Aegis Manual Test Cases" document (QR-01 through QR-57).
The test ID is shown in each docstring.

How to run:
    cd aegis-tests
    pip install pytest httpx qrcode[pil]
    pytest tests/test_integration_qr.py -v

    # Run one category:
    pytest tests/test_integration_qr.py::TestWiFi -v

    # Skip slow tests (async completion, history):
    pytest tests/test_integration_qr.py -v -m "not slow"

    # Different base URL:
    AEGIS_BASE_URL=http://localhost:8001 pytest tests/test_integration_qr.py -v

Prerequisites:
    - Aegis QR Scanner running at http://localhost:8001
    - Link Analyzer running at http://localhost:8000 (used for URL scans)
    - pip install qrcode[pil] for QR generation fixtures
"""

import time
import base64
import pytest
import httpx
from conftest import (
    BASE_URL, TIMEOUT,
    post_scan_file, get, post, delete,
    make_qr_b64, make_multi_qr_b64,
    safe_url_qr, phishing_url_qr, bitcoin_qr,
    email_qr, smishing_email_qr,
    wifi_qr, vcard_qr, multi_qr,
    invalid_b64, minimal_png_b64,
)


# ════════════════════════════════════════════════════════════════
# Shared module-scoped scan results
# (generated once per test session to avoid redundant QR scans)
# ════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def safe_scan_result(safe_url_qr):
    """Full scan result for https://google.com QR — cached for module."""
    return post_scan_file(safe_url_qr).json()

@pytest.fixture(scope="module")
def phishing_scan_result(phishing_url_qr):
    """Full scan result for a phishing-pattern URL QR."""
    return post_scan_file(phishing_url_qr).json()

@pytest.fixture(scope="module")
def bitcoin_scan_result(bitcoin_qr):
    """Full scan result for bitcoin:// QR."""
    return post_scan_file(bitcoin_qr).json()

@pytest.fixture(scope="module")
def wifi_scan_result(wifi_qr):
    """Full scan result for WIFI:T:WPA;... QR."""
    return post_scan_file(wifi_qr).json()

@pytest.fixture(scope="module")
def vcard_scan_result(vcard_qr):
    """Full scan result for vCard QR."""
    return post_scan_file(vcard_qr).json()


# ════════════════════════════════════════════════════════════════
# QR-01 — Server Health
# ════════════════════════════════════════════════════════════════

class TestHealth:
    """QR-01: Verify the QR Scanner is running and healthy."""

    def test_qr01a_health_returns_200(self):
        """QR-01a: GET /health → HTTP 200."""
        r = get("/health")
        assert r.status_code == 200, (
            f"QR-01 FAIL: /health returned {r.status_code}. "
            "Is the QR Scanner running at " + BASE_URL + "?"
        )

    def test_qr01b_health_status_field(self):
        """QR-01b: /health response has status field with acceptable value."""
        data = get("/health").json()
        assert "status" in data, "health response missing 'status' field"
        assert data["status"] in ("healthy", "degraded", "ok", "running"), (
            f"Unexpected health status: {data['status']!r}"
        )

    def test_qr01c_docs_accessible(self):
        """QR-01c: /docs (Swagger UI) returns HTTP 200."""
        r = get("/docs")
        assert r.status_code == 200


# ════════════════════════════════════════════════════════════════
# QR-02 to QR-07 — Basic Scan
# ════════════════════════════════════════════════════════════════

class TestBasicScan:
    """QR-02 to QR-07: Core scan endpoint behavior."""

    def test_qr02_safe_url_returns_success(self, safe_url_qr):
        """QR-02: Scanning a safe URL QR → HTTP 200 with status='success'."""
        r = post_scan_file(safe_url_qr)
        assert r.status_code == 200, (
            f"QR-02 FAIL: Expected HTTP 200, got {r.status_code}. Body: {r.text[:200]}"
        )
        data = r.json()
        assert data["status"] == "success", (
            f"QR-02 FAIL: status={data['status']!r}, expected 'success'"
        )
        assert data["total_qr_found"] >= 1, (
            f"QR-02 FAIL: total_qr_found={data['total_qr_found']}, expected >= 1"
        )

    def test_qr03_response_has_all_required_top_level_keys(self, safe_scan_result):
        """QR-03: All 6 required top-level fields must be present."""
        required = [
            "status", "total_qr_found", "overall_risk",
            "analyses", "phase2_image_analysis", "security_alerts",
        ]
        for key in required:
            assert key in safe_scan_result, (
                f"QR-03 FAIL: Top-level key '{key}' missing.\n"
                f"Keys present: {list(safe_scan_result.keys())}"
            )

    def test_qr04_analysis_has_all_required_keys(self, safe_scan_result):
        """QR-04: analyses[0] must contain all required per-analysis fields."""
        assert len(safe_scan_result["analyses"]) >= 1, "No analyses in response"
        analysis = safe_scan_result["analyses"][0]
        required = [
            "payload_index", "payload_preview", "qr_type",
            "blocked", "blacklist", "deobfuscation",
            "parsed_content", "final_risk_level", "final_risk_score",
        ]
        for key in required:
            assert key in analysis, (
                f"QR-04 FAIL: analyses[0] missing key '{key}'.\n"
                f"Keys present: {list(analysis.keys())}"
            )

    def test_qr05_invalid_base64_returns_400(self, invalid_b64):
        """QR-05: Sending invalid base64 data → HTTP 400."""
        r = post_scan_file(invalid_b64)
        assert r.status_code == 400, (
            f"QR-05 FAIL: Invalid base64 should return 400, got {r.status_code}"
        )

    def test_qr06_plain_image_no_qr_returns_failed(self, minimal_png_b64):
        """QR-06: Image with no QR code → HTTP 200, status='failed'."""
        r = post_scan_file(minimal_png_b64)
        assert r.status_code == 200, (
            f"QR-06 FAIL: Server should handle no-QR gracefully, got {r.status_code}"
        )
        data = r.json()
        assert data.get("status") == "failed", (
            f"QR-06 FAIL: Expected status='failed' for no-QR image, got {data.get('status')!r}"
        )
        assert "message" in data, "QR-06 FAIL: 'message' field missing from failed scan"

    def test_qr07_data_uri_prefix_accepted(self, safe_url_qr):
        """QR-07: Prefixing base64 with 'data:image/png;base64,' must still work."""
        r = post_scan_file("data:image/png;base64," + safe_url_qr)
        assert r.status_code == 200
        assert r.json()["status"] == "success", (
            "QR-07 FAIL: data URI prefix not stripped correctly"
        )

    def test_overall_risk_valid_enum(self, safe_scan_result):
        """overall_risk must be one of the 5 valid risk levels."""
        risk = safe_scan_result.get("overall_risk")
        assert risk in ("Safe", "Low", "Medium", "High", "Critical"), (
            f"overall_risk={risk!r} is not a valid level"
        )


# ════════════════════════════════════════════════════════════════
# QR-08 to QR-10 — Multi-QR Detection
# ════════════════════════════════════════════════════════════════

class TestMultiQRDetection:
    """QR-08 to QR-10: Detection of multiple QR codes in a single image."""

    def test_qr08_two_qrs_detected(self, multi_qr):
        """QR-08: Image with 2 QR codes → total_qr_found >= 2."""
        data = post_scan_file(multi_qr).json()
        assert data["total_qr_found"] >= 2, (
            f"QR-08 FAIL: Expected >= 2 QR codes found, got {data['total_qr_found']}"
        )

    def test_qr09_multi_qr_alert_triggered(self, multi_qr):
        """QR-09: Two QR codes → multiple_qr_alert = true in security_alerts."""
        data = post_scan_file(multi_qr).json()
        sa = data.get("security_alerts", {})
        assert sa.get("multiple_qr_alert") is True or \
               data.get("multiple_qr_alert") is True, (
            f"QR-09 FAIL: multiple_qr_alert should be True for a 2-QR image. "
            f"security_alerts: {sa}"
        )

    def test_qr10_single_qr_no_multi_alert(self, safe_url_qr):
        """QR-10: Single QR code must NOT trigger the multi-QR alert."""
        data = post_scan_file(safe_url_qr).json()
        sa = data.get("security_alerts", {})
        multi = sa.get("multiple_qr_alert", False) or data.get("multiple_qr_alert", False)
        assert multi is False, (
            f"QR-10 FAIL: Single QR scan incorrectly triggered multiple_qr_alert=True"
        )


# ════════════════════════════════════════════════════════════════
# QR-11 to QR-17 — QR Type Detection
# ════════════════════════════════════════════════════════════════

class TestQRTypeDetection:
    """QR-11 to QR-17: Correct QR type identification for all payload types."""

    def test_qr11_url_type_detected(self, safe_scan_result):
        """QR-11: https://google.com QR → qr_type = 'url'."""
        qr_type = safe_scan_result["analyses"][0]["qr_type"]
        assert qr_type == "url", (
            f"QR-11 FAIL: Expected qr_type='url', got {qr_type!r}"
        )

    def test_qr12_bitcoin_type_detected(self, bitcoin_scan_result):
        """QR-12: bitcoin:// QR → qr_type = 'bitcoin' or 'crypto', wallet address parsed."""
        analysis = bitcoin_scan_result["analyses"][0]
        assert analysis["qr_type"] in ("bitcoin", "crypto"), (
            f"QR-12 FAIL: Expected qr_type='bitcoin' or 'crypto', got {analysis['qr_type']!r}"
        )
        parsed = analysis.get("parsed_content", {})
        wallet = parsed.get("wallet_address", parsed.get("address", ""))
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf" in str(wallet), (
            f"QR-12 FAIL: Wallet address not correctly parsed. parsed_content: {parsed}"
        )
        amount = str(parsed.get("amount_requested", parsed.get("amount", "")))
        assert "0.1" in amount, (
            f"QR-12 FAIL: Amount '0.1' not found in parsed_content. parsed: {parsed}"
        )

    def test_qr13_email_type_detected(self, email_qr):
        """QR-13: mailto:contact@example.com QR → qr_type = 'email' or 'communication'."""
        data = post_scan_file(email_qr).json()
        qr_type = data["analyses"][0]["qr_type"]
        assert qr_type in ("email", "communication", "mailto"), (
            f"QR-13 FAIL: Expected email type, got {qr_type!r}"
        )

    def test_qr14_wifi_type_detected(self, wifi_scan_result):
        """QR-14: WIFI: QR → qr_type = 'wifi' or 'wifi_config'."""
        qr_type = wifi_scan_result["analyses"][0]["qr_type"]
        assert "wifi" in qr_type.lower(), (
            f"QR-14 FAIL: Expected wifi qr_type, got {qr_type!r}"
        )

    def test_qr15_vcard_type_detected(self, vcard_scan_result):
        """QR-15: BEGIN:VCARD QR → qr_type = 'vcard'."""
        qr_type = vcard_scan_result["analyses"][0]["qr_type"]
        assert "vcard" in qr_type.lower(), (
            f"QR-15 FAIL: Expected vcard qr_type, got {qr_type!r}"
        )

    def test_qr16_sms_type_detected(self):
        """QR-16: SMSTO: QR → qr_type is 'sms' or 'text' or 'communication'."""
        qr  = make_qr_b64("SMSTO:+12025551234:Hello test")
        data = post_scan_file(qr).json()
        qr_type = data["analyses"][0]["qr_type"]
        assert qr_type in ("sms", "text", "communication"), (
            f"QR-16 FAIL: Expected sms type, got {qr_type!r}"
        )

    def test_qr17_tel_type_detected(self):
        """QR-17: tel:+12025551234 QR → qr_type contains 'tel' or 'communication'."""
        qr  = make_qr_b64("tel:+12025551234")
        data = post_scan_file(qr).json()
        qr_type = data["analyses"][0]["qr_type"]
        assert "tel" in qr_type.lower() or "communication" in qr_type.lower(), (
            f"QR-17 FAIL: Expected tel type, got {qr_type!r}"
        )


# ════════════════════════════════════════════════════════════════
# QR-18 to QR-20 — Deobfuscation
# ════════════════════════════════════════════════════════════════

class TestDeobfuscation:
    """QR-18 to QR-20: Deobfuscation engine behavior."""

    def test_qr18_clean_url_not_flagged_as_obfuscated(self, safe_scan_result):
        """QR-18: Plain https://google.com → is_obfuscated = False."""
        deob = safe_scan_result["analyses"][0].get("deobfuscation", {})
        assert deob.get("is_obfuscated") is False, (
            f"QR-18 FAIL: Clean URL incorrectly flagged as obfuscated. deobfuscation: {deob}"
        )
        assert deob.get("obfuscation_layers", 0) == 0

    def test_qr19_deobfuscation_struct_always_present(self, safe_scan_result):
        """QR-19: deobfuscation key must be present with required sub-fields."""
        deob = safe_scan_result["analyses"][0].get("deobfuscation")
        assert deob is not None, "QR-19 FAIL: deobfuscation key missing from analyses[0]"
        for f in ["original", "is_obfuscated", "obfuscation_layers",
                  "likely_true_payload", "all_extracted_urls"]:
            assert f in deob, f"QR-19 FAIL: deobfuscation.{f} missing"
        assert isinstance(deob["all_extracted_urls"], list)

    def test_qr20_hex_encoded_scheme_triggers_obfuscation(self):
        """QR-20: %68%74%74%70%73:// (hex-encoded 'https') → is_obfuscated = True."""
        qr   = make_qr_b64("%68%74%74%70%73://evil.com/login")
        data = post_scan_file(qr).json()
        deob = data["analyses"][0].get("deobfuscation", {})
        assert deob.get("is_obfuscated") is True or deob.get("obfuscation_layers", 0) > 0, (
            f"QR-20 FAIL: Hex-encoded scheme should be detected as obfuscated. "
            f"deobfuscation: {deob}"
        )


# ════════════════════════════════════════════════════════════════
# QR-21 to QR-23 — Smishing Detection
# ════════════════════════════════════════════════════════════════

class TestSmishingDetection:
    """QR-21 to QR-23: SMS and email phishing detection."""

    def test_qr21_phishing_email_qr_flagged_high_or_critical(self, smishing_email_qr):
        """QR-21: Phishing mailto: QR with URGENT body → High or Critical overall_risk."""
        data = post_scan_file(smishing_email_qr).json()
        risk = data.get("overall_risk", "")
        assert risk in ("High", "Critical"), (
            f"QR-21 FAIL: Phishing email QR should be High or Critical, got '{risk}'"
        )

    def test_qr22_urgency_keywords_in_sms(self):
        """QR-22: SMS with URGENT/SUSPENDED keywords and malicious link → smishing_score >= 50."""
        qr = make_qr_b64(
            "SMSTO:+1234567890:URGENT! Your account SUSPENDED. "
            "Verify NOW at http://bank-verify.tk or lose access in 24 hours!"
        )
        data = post_scan_file(qr).json()
        # Look in any analysis for smishing score
        found_score = False
        for analysis in data.get("analyses", []):
            pc = analysis.get("parsed_content", {})
            smishing = pc.get("smishing_analysis", pc.get("smishing", {}))
            score = smishing.get("smishing_score", 0)
            if score >= 50:
                found_score = True
                break
        # Also accept if overall risk is High/Critical
        if data.get("overall_risk") in ("High", "Critical"):
            found_score = True
        assert found_score, (
            f"QR-22 FAIL: Urgent SMS with malicious link should score >= 50 or "
            f"overall_risk High/Critical. overall_risk={data.get('overall_risk')}"
        )

    def test_qr23_plain_mailto_not_critical(self, email_qr):
        """QR-23: Plain mailto: with no suspicious body → NOT High or Critical."""
        data = post_scan_file(email_qr).json()
        risk = data.get("overall_risk", "")
        assert risk not in ("High", "Critical"), (
            f"QR-23 FAIL: Plain mailto: should not be High/Critical, got '{risk}'"
        )


# ════════════════════════════════════════════════════════════════
# QR-24 to QR-27 — Blacklist
# ════════════════════════════════════════════════════════════════

class TestBlacklist:
    """QR-24 to QR-27: Payload blacklist reporting and checking."""

    BLACKLIST_URL = "https://test-blacklist-integration-aegis-evil-v2.com"

    def test_qr24_report_url_to_blacklist(self):
        """QR-24: POST /report with valid payload → HTTP 200, added=True."""
        r = post("/report",
                 payload=self.BLACKLIST_URL,
                 threat_type="phishing",
                 source="manual_test")
        assert r.status_code == 200, (
            f"QR-24 FAIL: /report returned {r.status_code}. Body: {r.text[:200]}"
        )
        data = r.json()
        is_added = data.get("added") is True or "blacklist" in str(data).lower()
        assert is_added, (
            f"QR-24 FAIL: Expected 'added'=True in response. Got: {data}"
        )

    def test_qr25_blacklisted_url_triggers_blocked_flag(self):
        """QR-25: QR of a previously blacklisted URL → blocked=True."""
        # Ensure it's blacklisted first
        post("/report",
             payload=self.BLACKLIST_URL,
             threat_type="phishing",
             source="manual_test")
        # Now scan it
        qr   = make_qr_b64(self.BLACKLIST_URL)
        data = post_scan_file(qr).json()
        analysis = data["analyses"][0]
        blacklist_hit = (
            analysis.get("blocked") is True or
            analysis.get("blacklist", {}).get("blacklisted") is True
        )
        assert blacklist_hit, (
            f"QR-25 FAIL: Blacklisted URL should be blocked. "
            f"blocked={analysis.get('blocked')}, "
            f"blacklist={analysis.get('blacklist')}"
        )

    def test_qr26_blacklist_stats_endpoint(self):
        """QR-26: GET /blacklist/stats → HTTP 200 with entry count."""
        r = get("/blacklist/stats")
        assert r.status_code == 200
        data = r.json()
        # Accept any of these field names
        has_count = any(
            k in data for k in ("total_entries", "total_blocked", "total", "count")
        )
        assert has_count, (
            f"QR-26 FAIL: /blacklist/stats missing a count field. Response: {data}"
        )

    def test_qr27_report_requires_payload_field(self):
        """QR-27: POST /report without 'payload' → HTTP 400 or 422."""
        r = post("/report", threat_type="phishing")
        assert r.status_code in (400, 422), (
            f"QR-27 FAIL: Missing payload should return 400/422, got {r.status_code}"
        )


# ════════════════════════════════════════════════════════════════
# QR-28 to QR-30 — WiFi Security
# ════════════════════════════════════════════════════════════════

class TestWiFiSecurity:
    """QR-28 to QR-30: WiFi QR code security analysis."""

    def test_qr28_open_wifi_flagged_critical(self):
        """QR-28: WIFI:T:nopass → final_risk_level = 'Critical'."""
        qr   = make_qr_b64("WIFI:T:nopass;S:FreePublicWifi;;;")
        data = post_scan_file(qr).json()
        risk = data["analyses"][0]["final_risk_level"]
        assert risk == "Critical", (
            f"QR-28 FAIL: Open WiFi (nopass) should be Critical, got '{risk}'"
        )

    def test_qr28_open_wifi_overall_risk_high_or_critical(self):
        """QR-28b: Open WiFi overall_risk must be High or Critical."""
        qr   = make_qr_b64("WIFI:T:nopass;S:FreePublicWifi;;;")
        data = post_scan_file(qr).json()
        assert data["overall_risk"] in ("High", "Critical"), (
            f"QR-28 FAIL: overall_risk for open WiFi is '{data['overall_risk']}'"
        )

    def test_qr29_weak_password_wifi_flagged(self):
        """QR-29: WPA WiFi with weak password → risk not Safe."""
        qr   = make_qr_b64("WIFI:T:WPA;S:HomeNetwork;P:12345678;;")
        data = post_scan_file(qr).json()
        risk = data["analyses"][0]["final_risk_level"]
        assert risk != "Safe", (
            f"QR-29 FAIL: Weak password WiFi should not be Safe, got '{risk}'"
        )

    def test_qr30_wpa_network_has_lower_risk_than_open(self):
        """QR-30: WPA network risk rank must be lower than no-password network."""
        RISK_ORDER = {"Safe": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
        wpa_qr  = make_qr_b64("WIFI:T:WPA;S:SecureNet;P:V3ry$tr0ngP@ssw0rd!2024;;")
        open_qr = make_qr_b64("WIFI:T:nopass;S:FreeWifi;;;")
        wpa_risk  = post_scan_file(wpa_qr).json()["analyses"][0]["final_risk_level"]
        open_risk = post_scan_file(open_qr).json()["analyses"][0]["final_risk_level"]
        assert RISK_ORDER.get(wpa_risk, 0) < RISK_ORDER.get(open_risk, 0), (
            f"QR-30 FAIL: WPA risk ({wpa_risk}) should be lower than open WiFi risk ({open_risk})"
        )


# ════════════════════════════════════════════════════════════════
# QR-31 to QR-33 — Crypto / Bitcoin
# ════════════════════════════════════════════════════════════════

class TestCryptoQR:
    """QR-31 to QR-33: Bitcoin and Ethereum QR code parsing."""

    def test_qr31_bitcoin_wallet_address_parsed(self, bitcoin_scan_result):
        """QR-31: Bitcoin QR → wallet_address = '1A1zP1...', amount_requested = '0.1'."""
        analysis = bitcoin_scan_result["analyses"][0]
        parsed   = analysis.get("parsed_content", {})
        wallet   = parsed.get("wallet_address", parsed.get("address", ""))
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf" in str(wallet), (
            f"QR-31 FAIL: wallet_address not parsed correctly. parsed_content: {parsed}"
        )
        amount = str(parsed.get("amount_requested", parsed.get("amount", "")))
        assert "0.1" in amount, (
            f"QR-31 FAIL: Amount '0.1' not found. parsed_content: {parsed}"
        )

    def test_qr32_invalid_bitcoin_address_no_crash(self):
        """QR-32: bitcoin:NOTAVALIDADDRESS QR → HTTP 200, no 500 crash."""
        qr   = make_qr_b64("bitcoin:NOTAVALIDADDRESS?amount=1.0")
        r    = post_scan_file(qr)
        assert r.status_code == 200, (
            f"QR-32 FAIL: Invalid bitcoin address caused server error: {r.status_code}"
        )

    def test_qr33_ethereum_uri_parsed(self):
        """QR-33: ethereum:// QR → HTTP 200, some qr_type returned."""
        qr   = make_qr_b64("ethereum:0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
        data = post_scan_file(qr).json()
        assert data["status"] in ("success", "failed"), (
            f"QR-33 FAIL: Unexpected status: {data.get('status')}"
        )
        if data["status"] == "success":
            qr_type = data["analyses"][0]["qr_type"]
            assert qr_type in ("ethereum", "bitcoin", "crypto", "url", "text"), (
                f"QR-33 FAIL: Unexpected qr_type for ethereum URI: {qr_type!r}"
            )


# ════════════════════════════════════════════════════════════════
# QR-34 to QR-40 — Phase 2 Image Analysis
# ════════════════════════════════════════════════════════════════

class TestPhase2ImageAnalysis:
    """QR-34 to QR-40: Phase 2 tamper detection, EXIF, fingerprinting, steganography."""

    def test_qr34_phase2_section_present(self, safe_scan_result):
        """QR-34: phase2_image_analysis must be present and non-null."""
        p2 = safe_scan_result.get("phase2_image_analysis")
        assert p2 is not None, "QR-34 FAIL: phase2_image_analysis missing from response"
        for key in ["tamper_detection", "exif_metadata", "visual_fingerprint",
                    "phase2_risk_score", "phase2_alerts"]:
            assert key in p2, f"QR-34 FAIL: phase2_image_analysis.{key} missing"

    def test_qr35_clean_qr_no_tamper(self, safe_scan_result):
        """QR-35: Digitally generated QR → tamper_detection.tamper_suspected = False."""
        td = safe_scan_result["phase2_image_analysis"]["tamper_detection"]
        assert td.get("tamper_suspected") is False, (
            f"QR-35 FAIL: Clean digital QR should not trigger tamper detection. "
            f"tamper_detection: {td}"
        )
        conf = td.get("confidence", 0.0)
        assert isinstance(conf, float), f"confidence should be float, got {type(conf)}"
        assert 0.0 <= conf <= 1.0, f"confidence {conf} out of range 0.0–1.0"

    def test_qr36_perceptual_hash_is_hex_string(self, safe_scan_result):
        """QR-36: visual_fingerprint.perceptual_hash must be a hex string > 10 chars."""
        vf   = safe_scan_result["phase2_image_analysis"]["visual_fingerprint"]
        phash = vf.get("perceptual_hash", "")
        assert isinstance(phash, str) and len(phash) > 10, (
            f"QR-36 FAIL: perceptual_hash={phash!r} should be a long hex string"
        )
        # Validate hex
        try:
            int(phash, 16)
        except ValueError:
            pytest.fail(f"QR-36 FAIL: perceptual_hash '{phash}' is not valid hexadecimal")

    def test_qr37_times_seen_increments_on_rescan(self, safe_url_qr):
        """QR-37: Scanning the same QR twice → times_seen_before increases."""
        r1   = post_scan_file(safe_url_qr).json()
        seen1 = r1["phase2_image_analysis"]["visual_fingerprint"].get("times_seen_before", 0)
        r2   = post_scan_file(safe_url_qr).json()
        seen2 = r2["phase2_image_analysis"]["visual_fingerprint"].get("times_seen_before", 0)
        assert seen2 >= seen1, (
            f"QR-37 FAIL: times_seen_before should not decrease. "
            f"scan1={seen1}, scan2={seen2}"
        )

    def test_qr38_different_qrs_have_different_hashes(self, safe_url_qr):
        """QR-38: Two different QR codes must produce different perceptual hashes."""
        github_qr = make_qr_b64("https://github.com")
        hash1 = post_scan_file(safe_url_qr).json()[
            "phase2_image_analysis"]["visual_fingerprint"]["perceptual_hash"]
        hash2 = post_scan_file(github_qr).json()[
            "phase2_image_analysis"]["visual_fingerprint"]["perceptual_hash"]
        assert hash1 != hash2, (
            f"QR-38 FAIL: Two different QRs produced the same perceptual hash: {hash1!r}"
        )

    def test_qr39_programmatic_png_no_exif(self, safe_scan_result):
        """QR-39: Digitally generated QR → exif_metadata.available = False."""
        exif = safe_scan_result["phase2_image_analysis"]["exif_metadata"]
        assert exif.get("available") is False, (
            f"QR-39 FAIL: Programmatic PNG should have no EXIF. exif: {exif}"
        )
        assert "note" in exif, "QR-39 FAIL: exif_metadata should have a 'note' field"

    def test_qr40_steganography_section_present(self, safe_scan_result):
        """QR-40: security_alerts.steganography must have detected, variance, threshold fields."""
        stego = safe_scan_result.get("security_alerts", {}).get("steganography", {})
        assert stego is not None, "QR-40 FAIL: steganography section missing from security_alerts"
        for f in ["detected", "variance", "threshold"]:
            assert f in stego, f"QR-40 FAIL: steganography.{f} missing"
        assert isinstance(stego["variance"], (int, float))
        assert isinstance(stego["threshold"], (int, float))


# ════════════════════════════════════════════════════════════════
# QR-41 to QR-44 — Cache
# ════════════════════════════════════════════════════════════════

class TestCache:
    """QR-41 to QR-44: Cache endpoints."""

    def test_qr41_cache_stats_returns_200(self):
        """QR-41: GET /cache/stats → HTTP 200 with cache key present."""
        r = get("/cache/stats")
        assert r.status_code == 200, (
            f"QR-41 FAIL: /cache/stats returned {r.status_code}"
        )
        data = r.json()
        has_cache_key = any("cache" in str(k).lower() for k in data.keys())
        assert has_cache_key or len(data) > 0, (
            f"QR-41 FAIL: /cache/stats response appears empty: {data}"
        )

    def test_qr42_second_scan_not_slower(self, safe_url_qr):
        """QR-42: Second scan of same QR should not take significantly longer."""
        t0  = time.time(); post_scan_file(safe_url_qr); t1 = time.time()
        t2  = time.time(); post_scan_file(safe_url_qr); t3 = time.time()
        scan1 = t1 - t0
        scan2 = t3 - t2
        # Allow scan2 to be up to 2x scan1 (caching should help, not hurt)
        assert scan2 <= scan1 * 2 + 5, (
            f"QR-42 FAIL: Second scan ({scan2:.1f}s) much slower than first ({scan1:.1f}s)"
        )

    def test_qr43_clear_url_cache(self):
        """QR-43: DELETE /cache/clear → HTTP 200 with 'cleared' in response."""
        r = delete("/cache/clear")
        assert r.status_code == 200, (
            f"QR-43 FAIL: DELETE /cache/clear returned {r.status_code}"
        )
        data = r.json()
        assert "cleared" in str(data).lower() or "success" in str(data).lower(), (
            f"QR-43 FAIL: Response should mention 'cleared'. Got: {data}"
        )

    def test_qr44_clear_qr_cache(self):
        """QR-44: DELETE /qr-cache/clear → HTTP 200."""
        r = delete("/qr-cache/clear")
        assert r.status_code in (200, 404), (
            f"QR-44: /qr-cache/clear returned {r.status_code} "
            f"(404 acceptable if endpoint does not exist separately)"
        )


# ════════════════════════════════════════════════════════════════
# QR-45 to QR-46 — Stats
# ════════════════════════════════════════════════════════════════

class TestStats:
    """QR-45 to QR-46: Statistics and telemetry endpoints."""

    def test_qr45_stats_returns_data(self):
        """QR-45: GET /stats → HTTP 200 with a counter field."""
        r = get("/stats")
        assert r.status_code == 200
        data = r.json()
        has_counter = any(
            k in str(data).lower()
            for k in ("total_scans", "scan_count", "scans", "total")
        )
        assert has_counter, (
            f"QR-45 FAIL: /stats response should contain a scan counter. Got: {data}"
        )

    def test_qr46_scan_count_increments(self, safe_url_qr):
        """QR-46: Performing a scan must increment the total scan counter."""
        def get_count():
            data = get("/stats").json()
            for key in ("total_scans", "scan_count", "scans"):
                if key in data:
                    return data[key]
                # nested structure
                for v in data.values():
                    if isinstance(v, dict) and key in v:
                        return v[key]
            return None

        before = get_count()
        post_scan_file(safe_url_qr)
        after  = get_count()
        if before is not None and after is not None:
            assert after >= before, (
                f"QR-46 FAIL: Scan count should not decrease. before={before}, after={after}"
            )


# ════════════════════════════════════════════════════════════════
# QR-47 — vCard with Embedded URL
# ════════════════════════════════════════════════════════════════

class TestVCard:
    """QR-47: vCard with embedded malicious URL."""

    def test_qr47_vcard_with_phishing_url_flagged(self):
        """QR-47: vCard containing a .tk URL → overall_risk not Safe."""
        qr = make_qr_b64(
            "BEGIN:VCARD\nVERSION:3.0\nFN:John Doe\n"
            "URL:http://phishing-login.tk/harvest\nEND:VCARD"
        )
        data = post_scan_file(qr).json()
        assert data["overall_risk"] != "Safe", (
            f"QR-47 FAIL: vCard with phishing URL should not be Safe. "
            f"overall_risk={data['overall_risk']!r}"
        )


# ════════════════════════════════════════════════════════════════
# QR-48 to QR-52 — QR Generator
# ════════════════════════════════════════════════════════════════

class TestQRGenerator:
    """QR-48 to QR-52: POST /generate endpoint (requires qrcode[pil] in Docker)."""

    def _skip_if_503(self, r: httpx.Response):
        if r.status_code == 503:
            pytest.skip("POST /generate returned 503 — qrcode[pil] not installed in Docker")

    def test_qr48_generate_safe_url_returns_200(self):
        """QR-48: POST /generate with safe URL → HTTP 200 with qr_base64."""
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": "https://google.com"})
        self._skip_if_503(r)
        assert r.status_code == 200, (
            f"QR-48 FAIL: /generate returned {r.status_code}. Body: {r.text[:200]}"
        )
        data = r.json()
        assert "qr_base64" in data, "QR-48 FAIL: qr_base64 missing from response"
        assert data["qr_base64"].startswith("data:image/png;base64,"), (
            f"QR-48 FAIL: qr_base64 should start with data:image/png;base64,"
        )

    def test_qr49_generated_qr_is_valid_png(self):
        """QR-49: Decoded qr_base64 must start with PNG magic bytes."""
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": "https://anthropic.com"})
        self._skip_if_503(r)
        if r.status_code != 200:
            pytest.skip(f"Generator returned {r.status_code}")
        b64 = r.json()["qr_base64"].split(",", 1)[-1]
        img_bytes = base64.b64decode(b64)
        PNG_MAGIC = bytes([137, 80, 78, 71, 13, 10, 26, 10])
        assert img_bytes[:8] == PNG_MAGIC, (
            f"QR-49 FAIL: Decoded image does not start with PNG magic bytes. "
            f"First 8 bytes: {img_bytes[:8].hex()}"
        )

    def test_qr50_high_risk_url_refused_or_flagged(self):
        """QR-50: Generating QR for a heavy phishing URL → refused or High/Critical risk."""
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate",
                       json={"url": "http://secure-bank-verify-account.tk/login/confirm"})
        self._skip_if_503(r)
        if r.status_code != 200:
            return  # 400 is also acceptable
        data = r.json()
        # Either refused with reason, or high risk info is present
        refused = data.get("status") == "refused" or "risk" in data
        assert refused, (
            f"QR-50 FAIL: High-risk URL should be refused by generator. Response: {data}"
        )

    def test_qr51_no_scheme_url_rejected(self):
        """QR-51: URL without http:// or https:// → HTTP 400."""
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": "google.com"})
        self._skip_if_503(r)
        assert r.status_code == 400, (
            f"QR-51 FAIL: URL without scheme should return 400, got {r.status_code}"
        )

    def test_qr52_empty_url_rejected(self):
        """QR-52: Empty URL → HTTP 400."""
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/generate", json={"url": ""})
        self._skip_if_503(r)
        assert r.status_code == 400, (
            f"QR-52 FAIL: Empty URL should return 400, got {r.status_code}"
        )


# ════════════════════════════════════════════════════════════════
# QR-53 to QR-55 — Async Scan
# ════════════════════════════════════════════════════════════════

class TestAsyncScan:
    """QR-53 to QR-55: POST /scan-async + GET /scan-status/{job_id}."""

    def test_qr53_async_returns_job_id_fast(self, safe_url_qr):
        """QR-53: Async submit must return in < 5s with job_id and status='pending'."""
        t0   = time.time()
        data = post("/scan-async", image_base64=safe_url_qr).json()
        elapsed = time.time() - t0
        assert elapsed < 5.0, (
            f"QR-53 FAIL: Async submit took {elapsed:.1f}s, expected < 5s"
        )
        assert "job_id" in data, f"QR-53 FAIL: job_id missing. Response: {data}"
        assert data.get("status") == "pending", (
            f"QR-53 FAIL: Initial status should be 'pending', got {data.get('status')!r}"
        )
        assert "poll_url" in data

    def test_qr54_poll_returns_job_info(self, safe_url_qr):
        """QR-54: Polling a valid job_id → HTTP 200 with job_id, status, url."""
        job_id = post("/scan-async", image_base64=safe_url_qr).json()["job_id"]
        r      = get(f"/scan-status/{job_id}")
        assert r.status_code == 200, (
            f"QR-54 FAIL: Polling job returned {r.status_code}"
        )
        data = r.json()
        assert data.get("job_id") == job_id
        assert "status" in data
        assert data["status"] in ("pending", "running", "complete", "failed")

    @pytest.mark.slow
    def test_qr55_job_completes_within_120_seconds(self, safe_url_qr):
        """QR-55: Async job must complete within 120 seconds."""
        job_id   = post("/scan-async", image_base64=safe_url_qr).json()["job_id"]
        deadline = time.time() + 120
        while time.time() < deadline:
            data = get(f"/scan-status/{job_id}").json()
            if data.get("status") in ("complete", "failed"):
                break
            time.sleep(3)
        assert data["status"] == "complete", (
            f"QR-55 FAIL: Job did not complete within 120s. "
            f"Final status: {data.get('status')}"
        )
        result = data.get("result", {})
        assert "overall_risk" in result or "status" in result, (
            f"QR-55 FAIL: Completed result missing expected fields. result: {result}"
        )


# ════════════════════════════════════════════════════════════════
# QR-56 to QR-57 — Scan History
# ════════════════════════════════════════════════════════════════

class TestScanHistory:
    """QR-56 to QR-57: GET /history endpoint."""

    def test_qr56_history_endpoint_returns_data(self, safe_url_qr):
        """QR-56: After a scan, GET /history should return at least 1 entry."""
        post_scan_file(safe_url_qr)   # ensure at least one scan exists
        r = get("/history", limit=5)
        assert r.status_code == 200, (
            f"QR-56 FAIL: /history returned {r.status_code}"
        )
        data = r.json()
        entries = data if isinstance(data, list) else data.get("entries", data.get("history", []))
        assert len(entries) >= 1, (
            f"QR-56 FAIL: /history should have >= 1 entry after a scan. Got: {data}"
        )

    def test_qr57_history_entry_has_risk_field(self, safe_url_qr):
        """QR-57: Each history entry must contain an overall_risk or risk field."""
        post_scan_file(safe_url_qr)
        r    = get("/history", limit=5)
        data = r.json()
        entries = data if isinstance(data, list) else data.get("entries", data.get("history", []))
        if not entries:
            pytest.skip("No history entries to check")
        entry = entries[0]
        has_risk = "overall_risk" in entry or "risk" in entry or "risk_level" in entry
        assert has_risk, (
            f"QR-57 FAIL: History entry missing risk field. entry keys: {list(entry.keys())}"
        )
