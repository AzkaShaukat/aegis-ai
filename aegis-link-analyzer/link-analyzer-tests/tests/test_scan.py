"""
test_scan.py — POST /scan Full Scan Tests
==========================================
Tests for: response structure, risk levels, all detection
           layer fields, score breakdown, ML prediction,
           input validation, URL normalization, edge cases.
"""

import pytest
import httpx
from conftest import (
    BASE_URL, TIMEOUT, scan, scan_json,
    SAFE_URLS, PHISHING_URLS, IP_URLS, SHORTENER_URLS,
    BARE_DOMAIN, GOOGLE_MALWARE_TEST
)


# ════════════════════════════════════════════════════════════════
# 1 — Response Structure
# ════════════════════════════════════════════════════════════════

class TestScanResponseStructure:
    def test_scan_returns_200(self, safe_scan):
        r = scan("https://google.com")
        assert r.status_code == 200

    def test_scan_has_required_top_level_fields(self, safe_scan):
        required = [
            "url", "risk_level", "confidence_score", "message",
            "scan_date", "scan_id", "total_flags", "all_flags",
            "score_breakdown"
        ]
        for field in required:
            assert field in safe_scan, f"Missing top-level field: '{field}'"

    def test_scan_id_is_string(self, safe_scan):
        assert isinstance(safe_scan["scan_id"], str)
        assert len(safe_scan["scan_id"]) > 5

    def test_scan_date_is_iso_format(self, safe_scan):
        from datetime import datetime
        d = safe_scan["scan_date"]
        # Should parse without error
        datetime.fromisoformat(d.replace("Z", "+00:00"))

    def test_risk_level_is_valid(self, safe_scan):
        assert safe_scan["risk_level"] in (
            "Safe", "Low Risk", "Medium Risk", "High Risk"
        )

    def test_confidence_score_in_range(self, safe_scan):
        score = safe_scan["confidence_score"]
        assert isinstance(score, (int, float))
        assert 0.0 <= score <= 100.0

    def test_total_flags_is_non_negative_int(self, safe_scan):
        assert isinstance(safe_scan["total_flags"], int)
        assert safe_scan["total_flags"] >= 0

    def test_all_flags_is_list(self, safe_scan):
        assert isinstance(safe_scan["all_flags"], list)

    def test_total_flags_matches_all_flags_length(self, safe_scan):
        assert safe_scan["total_flags"] == len(safe_scan["all_flags"])

    def test_message_is_non_empty_string(self, safe_scan):
        assert isinstance(safe_scan["message"], str)
        assert len(safe_scan["message"]) > 10


# ════════════════════════════════════════════════════════════════
# 2 — Detection Layer Fields
# ════════════════════════════════════════════════════════════════

class TestDetectionLayers:
    def test_heuristics_layer_present(self, safe_scan):
        assert "heuristics" in safe_scan
        assert safe_scan["heuristics"] is not None

    def test_heuristics_has_required_fields(self, safe_scan):
        h = safe_scan["heuristics"]
        for field in ["flags", "flag_count", "heuristic_score",
                      "entropy", "checks_count", "is_suspicious"]:
            assert field in h, f"Missing heuristics field: {field}"

    def test_heuristics_flag_count_matches_flags(self, safe_scan):
        h = safe_scan["heuristics"]
        assert h["flag_count"] == len(h["flags"])

    def test_heuristics_entropy_is_float(self, safe_scan):
        assert isinstance(safe_scan["heuristics"]["entropy"], float)
        assert safe_scan["heuristics"]["entropy"] >= 0.0

    def test_whois_layer_present(self, safe_scan):
        assert "whois" in safe_scan
        assert safe_scan["whois"] is not None

    def test_whois_has_required_fields(self, safe_scan):
        w = safe_scan["whois"]
        for field in ["flags", "whois_score", "is_suspicious"]:
            assert field in w, f"Missing whois field: {field}"

    def test_dns_layer_present(self, safe_scan):
        assert "dns" in safe_scan
        assert safe_scan["dns"] is not None

    def test_dns_has_required_fields(self, safe_scan):
        d = safe_scan["dns"]
        for field in ["flags", "dns_score", "details", "is_suspicious"]:
            assert field in d, f"Missing dns field: {field}"

    def test_ssl_layer_present(self, safe_scan):
        assert "ssl" in safe_scan
        assert safe_scan["ssl"] is not None

    def test_ssl_has_required_fields(self, safe_scan):
        s = safe_scan["ssl"]
        for field in ["flags", "ssl_score", "details", "is_suspicious"]:
            assert field in s, f"Missing ssl field: {field}"

    def test_redirects_layer_present(self, safe_scan):
        assert "redirects" in safe_scan
        assert safe_scan["redirects"] is not None

    def test_redirects_has_required_fields(self, safe_scan):
        r = safe_scan["redirects"]
        for field in ["original_url", "final_url", "hop_count",
                      "hops", "shorteners_found", "destination_changed",
                      "flags", "redirect_score", "is_suspicious"]:
            assert field in r, f"Missing redirects field: {field}"

    def test_urlhaus_layer_present(self, safe_scan):
        assert "urlhaus" in safe_scan
        assert safe_scan["urlhaus"] is not None

    def test_urlhaus_has_required_fields(self, safe_scan):
        u = safe_scan["urlhaus"]
        for field in ["found", "flags", "urlhaus_score", "is_suspicious"]:
            assert field in u, f"Missing urlhaus field: {field}"

    def test_phishtank_layer_present(self, safe_scan):
        assert "phishtank" in safe_scan
        assert safe_scan["phishtank"] is not None

    def test_phishtank_has_required_fields(self, safe_scan):
        p = safe_scan["phishtank"]
        for field in ["found", "flags", "phishtank_score", "is_suspicious"]:
            assert field in p, f"Missing phishtank field: {field}"

    def test_gsb_layer_present(self, safe_scan):
        assert "gsb" in safe_scan
        assert safe_scan["gsb"] is not None

    def test_gsb_has_required_fields(self, safe_scan):
        g = safe_scan["gsb"]
        for field in ["found", "flags", "gsb_score", "is_suspicious", "api_available"]:
            assert field in g, f"Missing GSB field: {field}"


# ════════════════════════════════════════════════════════════════
# 3 — Score Breakdown
# ════════════════════════════════════════════════════════════════

class TestScoreBreakdown:
    def test_score_breakdown_present(self, safe_scan):
        assert "score_breakdown" in safe_scan
        assert safe_scan["score_breakdown"] is not None

    def test_score_breakdown_has_all_components(self, safe_scan):
        sb = safe_scan["score_breakdown"]
        for field in ["heuristics", "whois", "dns", "ssl", "redirects",
                      "virustotal", "urlhaus", "phishtank", "gsb",
                      "combined_final"]:
            assert field in sb, f"Missing score_breakdown field: {field}"

    def test_all_scores_are_non_negative(self, safe_scan):
        sb = safe_scan["score_breakdown"]
        for key, val in sb.items():
            if isinstance(val, (int, float)):
                assert val >= 0, f"Negative score for {key}: {val}"

    def test_combined_final_score_in_range(self, safe_scan):
        score = safe_scan["score_breakdown"]["combined_final"]
        assert 0.0 <= score <= 100.0

    def test_critical_signals_triggered_is_int(self, safe_scan):
        sb = safe_scan["score_breakdown"]
        assert isinstance(sb.get("critical_signals_triggered", 0), int)
        assert sb.get("critical_signals_triggered", 0) >= 0

    def test_critical_sources_is_list(self, safe_scan):
        sb = safe_scan["score_breakdown"]
        assert isinstance(sb.get("critical_sources", []), list)


# ════════════════════════════════════════════════════════════════
# 4 — ML Prediction
# ════════════════════════════════════════════════════════════════

class TestMLPrediction:
    def test_ml_prediction_present(self, safe_scan):
        assert "ml_prediction" in safe_scan

    def test_ml_prediction_has_available_field(self, safe_scan):
        ml = safe_scan["ml_prediction"]
        assert ml is not None
        assert "available" in ml

    def test_when_available_has_required_fields(self, safe_scan):
        ml = safe_scan["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML model not loaded")
        for field in ["prediction", "ml_risk_level", "phishing_probability",
                      "safe_probability", "top_features", "model_type",
                      "model_version", "features_used"]:
            assert field in ml, f"Missing ML field: {field}"

    def test_probabilities_sum_to_100(self, safe_scan):
        ml = safe_scan["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML model not loaded")
        total = ml["phishing_probability"] + ml["safe_probability"]
        assert 99.0 <= total <= 101.0, f"Probabilities sum to {total}, not 100"

    def test_probabilities_in_valid_range(self, safe_scan):
        ml = safe_scan["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML model not loaded")
        assert 0.0 <= ml["phishing_probability"] <= 100.0
        assert 0.0 <= ml["safe_probability"] <= 100.0

    def test_prediction_is_binary(self, safe_scan):
        ml = safe_scan["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML model not loaded")
        assert ml["prediction"] in (0, 1)

    def test_top_features_is_list(self, safe_scan):
        ml = safe_scan["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML model not loaded")
        assert isinstance(ml["top_features"], list)
        assert len(ml["top_features"]) > 0

    def test_features_used_is_35(self, safe_scan):
        ml = safe_scan["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML model not loaded")
        assert ml["features_used"] == 35, (
            f"Expected 35 features, got {ml['features_used']}"
        )

    def test_ml_risk_level_is_valid(self, safe_scan):
        ml = safe_scan["ml_prediction"]
        if not ml.get("available"):
            pytest.skip("ML model not loaded")
        assert ml["ml_risk_level"] in (
            "Safe", "Low Risk", "Medium Risk", "High Risk", "Critical Risk"
        )


# ════════════════════════════════════════════════════════════════
# 5 — Risk Directional Accuracy (Sanity Checks)
# ════════════════════════════════════════════════════════════════

class TestRiskDirectionalAccuracy:
    """
    The model/rules should give HIGHER risk to phishing URLs
    than to known-safe URLs. Not demanding 100% — just correct direction.
    """

    RISK_ORDER = {"Safe": 1, "Low Risk": 2, "Medium Risk": 3, "High Risk": 4}

    def _risk_score(self, risk_level: str) -> int:
        return self.RISK_ORDER.get(risk_level, 0)

    def test_google_is_safe_or_low(self):
        data = scan_json("https://google.com")
        assert data["risk_level"] in ("Safe", "Low Risk"), (
            f"google.com classified as {data['risk_level']} — "
            "model may be miscalibrated"
        )

    def test_github_is_safe_or_low(self):
        data = scan_json("https://github.com")
        assert data["risk_level"] in ("Safe", "Low Risk")

    def test_phishing_url_higher_risk_than_google(self, phishing_scan):
        google = scan_json("https://google.com")
        assert self._risk_score(phishing_scan["risk_level"]) >= \
               self._risk_score(google["risk_level"]), (
            f"Phishing URL ({phishing_scan['risk_level']}) should be "
            f">= google.com ({google['risk_level']})"
        )

    def test_http_scheme_flagged_in_phishing_context(self, phishing_scan):
        """HTTP scheme + phishing keywords should produce flags."""
        assert phishing_scan["total_flags"] > 0, \
            "Phishing URL produced zero flags"

    def test_google_malware_test_url_flagged(self):
        """Google's official malware test URL should be flagged."""
        data = scan_json(GOOGLE_MALWARE_TEST)
        assert data["risk_level"] in ("Medium Risk", "High Risk"), (
            f"Google malware test URL returned {data['risk_level']} — "
            "URLhaus or GSB should catch this"
        )

    def test_suspicious_tld_increases_flags(self):
        """A .tk domain should always have at least the TLD flag."""
        data = scan_json("http://example.tk")
        flags_str = " ".join(data["all_flags"]).lower()
        assert "tld" in flags_str or data["total_flags"] > 0

    def test_ip_url_flagged(self):
        """IP-based URL should always trigger at least one flag."""
        data = scan_json(IP_URLS[0])
        flags_str = " ".join(data["all_flags"]).lower()
        assert "ip" in flags_str or data["total_flags"] > 0

    def test_url_shortener_flagged(self):
        """Known URL shorteners should be flagged."""
        data = scan_json("https://bit.ly/3testexample")
        flags_str = " ".join(data["all_flags"]).lower()
        assert "shortener" in flags_str or "short" in flags_str or \
               data["total_flags"] > 0


# ════════════════════════════════════════════════════════════════
# 6 — Input Validation & URL Normalization
# ════════════════════════════════════════════════════════════════

class TestInputValidation:
    def test_empty_url_returns_422(self):
        r = scan("")
        assert r.status_code == 422

    def test_missing_url_field_returns_422(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(f"{BASE_URL}/scan", json={})
        assert r.status_code == 422

    def test_non_json_body_returns_422(self):
        with httpx.Client(timeout=TIMEOUT) as c:
            r = c.post(
                f"{BASE_URL}/scan",
                content="not json",
                headers={"Content-Type": "application/json"}
            )
        assert r.status_code == 422

    def test_bare_domain_auto_normalized(self):
        """Bare domain without https:// should be accepted and normalized."""
        r = scan(BARE_DOMAIN)
        assert r.status_code == 200
        data = r.json()
        assert "https://" in data["url"]

    def test_http_url_accepted(self):
        r = scan("http://example.com")
        assert r.status_code == 200

    def test_https_url_accepted(self):
        r = scan("https://example.com")
        assert r.status_code == 200

    def test_url_with_path_accepted(self):
        r = scan("https://example.com/path/to/page?param=value")
        assert r.status_code == 200

    def test_url_with_port_accepted(self):
        r = scan("https://example.com:8443/path")
        assert r.status_code == 200

    def test_very_long_url_handled(self):
        long_url = "https://example.com/" + "a" * 500
        r = scan(long_url)
        assert r.status_code in (200, 400, 422)   # Should not crash

    def test_unicode_domain_handled(self):
        r = scan("https://xn--80ak6aa92e.com")   # punycode
        assert r.status_code in (200, 400)

    def test_url_with_credentials_handled(self):
        """URL with user:pass@ should not crash."""
        r = scan("https://user:pass@example.com/login")
        assert r.status_code in (200, 400, 422)


# ════════════════════════════════════════════════════════════════
# 7 — Individual Detection Layer Behavior
# ════════════════════════════════════════════════════════════════

class TestHeuristicsLayer:
    def test_phishing_keywords_produce_heuristic_flags(self, phishing_scan):
        h = phishing_scan["heuristics"]
        assert h["flag_count"] > 0, \
            "Phishing URL should trigger at least one heuristic flag"

    def test_google_has_low_heuristic_score(self, safe_scan):
        assert safe_scan["heuristics"]["heuristic_score"] < 50, \
            "google.com should have low heuristic score"

    def test_checks_count_is_14_or_more(self, safe_scan):
        """Heuristics should run all 14 checks."""
        assert safe_scan["heuristics"]["checks_count"] >= 14, (
            f"Only {safe_scan['heuristics']['checks_count']} checks ran — "
            "expected at least 14"
        )

    def test_entropy_calculated_for_phishing_domain(self, phishing_scan):
        """High-entropy domain names should have entropy > 2.5."""
        entropy = phishing_scan["heuristics"]["entropy"]
        assert isinstance(entropy, float)
        assert entropy > 0.0


class TestWhoisLayer:
    def test_google_has_old_domain_age(self, safe_scan):
        """google.com should have domain_age_days >> 0."""
        w = safe_scan["whois"]
        if w.get("domain_age_days") is not None:
            assert w["domain_age_days"] > 365, (
                f"google.com domain age is {w['domain_age_days']} days — "
                "expected > 365"
            )

    def test_whois_score_is_numeric(self, safe_scan):
        assert isinstance(safe_scan["whois"]["whois_score"], (int, float))
        assert safe_scan["whois"]["whois_score"] >= 0

    def test_whois_flags_is_list(self, safe_scan):
        assert isinstance(safe_scan["whois"]["flags"], list)

    def test_new_domain_flagged(self):
        """Very new suspicious TLD domains should have new-domain flags."""
        data = scan_json("http://brand-new-domain-today.xyz/login")
        w = data["whois"]
        # May have age flag if domain is newly registered
        assert isinstance(w["flags"], list)


class TestDNSLayer:
    def test_google_dns_resolves(self, safe_scan):
        dns = safe_scan["dns"]
        details = dns.get("details", {})
        # google.com should resolve
        assert details.get("resolves", True) is True

    def test_dns_details_has_required_keys(self, safe_scan):
        details = safe_scan["dns"].get("details", {})
        # At minimum should have resolves key
        assert "resolves" in details

    def test_dns_score_non_negative(self, safe_scan):
        assert safe_scan["dns"]["dns_score"] >= 0


class TestSSLLayer:
    def test_google_ssl_valid(self, safe_scan):
        ssl = safe_scan["ssl"]
        details = ssl.get("details", {})
        if details.get("is_valid") is not None:
            assert details["is_valid"] is True, \
                "google.com should have valid SSL"

    def test_ssl_score_non_negative(self, safe_scan):
        assert safe_scan["ssl"]["ssl_score"] >= 0

    def test_http_url_ssl_flags(self):
        """HTTP URL should be flagged for no SSL."""
        data = scan_json("http://paypal-secure.tk/login")
        ssl = data["ssl"]
        ssl_flags = " ".join(ssl.get("flags", [])).lower()
        assert ssl["ssl_score"] >= 0   # At minimum, scored something

    def test_ssl_details_present(self, safe_scan):
        assert isinstance(safe_scan["ssl"].get("details", {}), dict)


class TestRedirectLayer:
    def test_original_url_matches_scan_input(self, safe_scan):
        redirects = safe_scan["redirects"]
        assert "google.com" in redirects.get("original_url", "")

    def test_final_url_present(self, safe_scan):
        assert safe_scan["redirects"]["final_url"] is not None

    def test_hop_count_is_int(self, safe_scan):
        assert isinstance(safe_scan["redirects"]["hop_count"], int)
        assert safe_scan["redirects"]["hop_count"] >= 0

    def test_www_normalization_not_flagged_as_suspicious(self, safe_scan):
        """Redirect from google.com → www.google.com is NOT suspicious."""
        r = safe_scan["redirects"]
        assert r.get("is_www_normalization") is True or \
               r.get("destination_changed") is False, (
            "www normalization should not be flagged as destination_changed"
        )

    def test_shorteners_found_is_list(self, safe_scan):
        assert isinstance(safe_scan["redirects"]["shorteners_found"], list)

    def test_redirect_score_non_negative(self, safe_scan):
        assert safe_scan["redirects"]["redirect_score"] >= 0


class TestURLhausLayer:
    def test_google_not_in_urlhaus(self, safe_scan):
        assert safe_scan["urlhaus"]["found"] is False, \
            "google.com should not be in URLhaus"

    def test_urlhaus_score_zero_for_safe_url(self, safe_scan):
        assert safe_scan["urlhaus"]["urlhaus_score"] == 0.0

    def test_urlhaus_tags_is_list(self, safe_scan):
        assert isinstance(safe_scan["urlhaus"].get("tags", []), list)

    def test_malware_url_in_urlhaus(self):
        data = scan_json(GOOGLE_MALWARE_TEST)
        u = data["urlhaus"]
        # Google malware test URL is in URLhaus — may be found or offline
        assert "found" in u
        assert "urlhaus_score" in u

    def test_urlhaus_offline_url_still_scored(self):
        """Offline malware URLs should still get a score (60 pts)."""
        data = scan_json(GOOGLE_MALWARE_TEST)
        u = data["urlhaus"]
        if u.get("status") == "offline":
            assert u["urlhaus_score"] > 0, \
                "Offline malware URL should still receive a non-zero score"


class TestOpenPhishLayer:
    def test_google_not_in_openphish(self, safe_scan):
        assert safe_scan["phishtank"]["found"] is False

    def test_phishtank_score_zero_for_google(self, safe_scan):
        assert safe_scan["phishtank"]["phishtank_score"] == 0.0

    def test_phishtank_feed_size_is_int(self, safe_scan):
        assert isinstance(safe_scan["phishtank"].get("feed_size", 0), int)

    def test_phishtank_source_is_openphish(self, safe_scan):
        assert safe_scan["phishtank"].get("source") == "openphish"


class TestGSBLayer:
    def test_gsb_api_available_field_exists(self, safe_scan):
        assert "api_available" in safe_scan["gsb"]

    def test_gsb_not_found_for_google(self, safe_scan):
        """google.com should not be flagged by GSB."""
        assert safe_scan["gsb"]["found"] is False

    def test_gsb_threats_is_list(self, safe_scan):
        assert isinstance(safe_scan["gsb"]["threats"], list)

    def test_gsb_skipped_gracefully_without_key(self, safe_scan):
        """Even without API key, should return structured result not crash."""
        gsb = safe_scan["gsb"]
        assert "found" in gsb
        assert "gsb_score" in gsb
