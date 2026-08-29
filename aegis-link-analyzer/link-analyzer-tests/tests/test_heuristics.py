"""
test_heuristics.py — URL Heuristic Engine Deep Tests
======================================================
Tests every individual heuristic check that the engine runs:
  suspicious TLD, phishing keywords, brand impersonation,
  IP address, URL shorteners, entropy, URL length,
  subdomains, special characters, HTTP scheme, data URIs, etc.

All tests run locally (no external API calls needed) so they
complete in < 5 seconds each.
"""

import pytest
from conftest import scan_json


def flags_for(url: str) -> list:
    """Return heuristics flags for a URL."""
    return scan_json(url)["heuristics"]["flags"]

def heuristic_score(url: str) -> float:
    return scan_json(url)["heuristics"]["heuristic_score"]

def is_suspicious(url: str) -> bool:
    return scan_json(url)["heuristics"]["is_suspicious"]

def entropy_for(url: str) -> float:
    return scan_json(url)["heuristics"]["entropy"]

def flags_str(url: str) -> str:
    return " ".join(flags_for(url)).lower()


# ════════════════════════════════════════════════════════════════
# 1 — Suspicious TLD
# ════════════════════════════════════════════════════════════════

class TestSuspiciousTLD:

    @pytest.mark.parametrize("tld_url", [
        "http://example.tk",
        "http://example.ml",
        "http://example.xyz",
        "http://example.ga",
        "http://example.cf",
        "http://example.gq",
        "http://example.top",
        "http://example.buzz",
        "http://example.click",
    ])
    def test_suspicious_tld_flagged(self, tld_url):
        f = flags_str(tld_url)
        assert "tld" in f or "suspicious" in f, \
            f"Expected TLD flag for {tld_url}, got: {flags_for(tld_url)}"

    def test_com_tld_not_flagged_for_tld(self):
        f = flags_str("https://example.com")
        assert "tld" not in f

    def test_org_tld_not_flagged_for_tld(self):
        f = flags_str("https://example.org")
        assert "tld" not in f


# ════════════════════════════════════════════════════════════════
# 2 — Phishing Keywords
# ════════════════════════════════════════════════════════════════

class TestPhishingKeywords:

    @pytest.mark.parametrize("keyword_url", [
        "https://example.com/login/verify",
        "https://example.com/account/update",
        "https://example.com/secure/signin",
        "https://example.com/verify/billing",
        "https://example.com/confirm/password",
        "https://example.com/recover/credential",
    ])
    def test_phishing_keyword_flagged(self, keyword_url):
        f = flags_str(keyword_url)
        assert "keyword" in f or "phishing" in f or "suspicious" in f, \
            f"Expected keyword flag for {keyword_url}, got: {flags_for(keyword_url)}"

    def test_clean_url_no_keyword_flags(self):
        data = scan_json("https://google.com")
        h = data["heuristics"]
        keyword_flags = [f for f in h["flags"] if "keyword" in f.lower()]
        assert len(keyword_flags) == 0


# ════════════════════════════════════════════════════════════════
# 3 — Brand Impersonation
# ════════════════════════════════════════════════════════════════

class TestBrandImpersonation:

    @pytest.mark.parametrize("brand_url", [
        "http://paypal-secure.tk/login",
        "http://amazon-account.xyz/verify",
        "http://google-verify.ml/signin",
        "http://microsoft-update.gq/account",
        "http://apple-account-alert.cf/confirm",
    ])
    def test_brand_impersonation_flagged(self, brand_url):
        f = flags_str(brand_url)
        assert "brand" in f or "impersonat" in f or \
               "keyword" in f or heuristic_score(brand_url) > 20, \
            f"Expected brand flag for {brand_url}, got: {flags_for(brand_url)}"

    def test_real_paypal_domain_not_flagged_as_impersonation(self):
        """paypal.com itself is not impersonating paypal."""
        f = flags_str("https://paypal.com")
        assert "brand" not in f or "impersonat" not in f


# ════════════════════════════════════════════════════════════════
# 4 — IP Address in URL
# ════════════════════════════════════════════════════════════════

class TestIPAddress:

    @pytest.mark.parametrize("ip_url", [
        "http://185.234.218.53/admin/login",
        "http://192.168.1.1/setup",
        "http://10.0.0.1/admin",
        "http://172.16.0.1/phishing.php",
        "https://93.184.216.34/secure/verify",
    ])
    def test_ip_address_url_flagged(self, ip_url):
        f = flags_str(ip_url)
        assert "ip" in f, \
            f"Expected IP flag for {ip_url}, got: {flags_for(ip_url)}"

    def test_domain_url_no_ip_flag(self):
        f = flags_str("https://google.com")
        assert "ip" not in f


# ════════════════════════════════════════════════════════════════
# 5 — URL Shorteners
# ════════════════════════════════════════════════════════════════

class TestURLShorteners:

    @pytest.mark.parametrize("short_url", [
        "https://bit.ly/3abc123",
        "https://tinyurl.com/testlink",
        "https://t.co/exampletest",
        "https://ow.ly/test1234",
        "https://is.gd/testlink",
        "https://rb.gy/testexample",
    ])
    def test_url_shortener_flagged(self, short_url):
        f = flags_str(short_url)
        assert "short" in f or "redirect" in f, \
            f"Expected shortener flag for {short_url}, got: {flags_for(short_url)}"

    def test_known_good_domain_not_flagged_as_shortener(self):
        f = flags_str("https://google.com/very/long/path/here")
        assert "short" not in f


# ════════════════════════════════════════════════════════════════
# 6 — HTTP vs HTTPS
# ════════════════════════════════════════════════════════════════

class TestHTTPScheme:

    def test_http_url_gets_higher_score_than_https(self):
        http_score  = heuristic_score("http://example.com/login")
        https_score = heuristic_score("https://example.com/login")
        assert http_score >= https_score, (
            f"http ({http_score}) should score >= https ({https_score})"
        )

    def test_http_url_flagged(self):
        f = flags_str("http://example.com/login")
        assert "http" in f or "ssl" in f or "scheme" in f, \
            f"Expected HTTP scheme flag, got: {flags_for('http://example.com/login')}"


# ════════════════════════════════════════════════════════════════
# 7 — URL Length & Entropy
# ════════════════════════════════════════════════════════════════

class TestURLLengthAndEntropy:

    def test_very_long_url_flagged(self):
        long_url = "https://example.com/" + "x" * 200
        f = flags_str(long_url)
        assert "length" in f or "long" in f or \
               heuristic_score(long_url) > heuristic_score("https://example.com"), \
            "Very long URL should increase heuristic score"

    def test_entropy_is_positive_for_any_url(self):
        e = entropy_for("https://google.com")
        assert e > 0.0

    def test_high_entropy_domain_has_higher_entropy(self):
        """Randomly-looking domain should have higher entropy than google.com."""
        normal = entropy_for("https://google.com")
        random_domain = entropy_for("https://xkf3j9a2q8z.com")
        assert random_domain >= normal, (
            f"Random domain entropy ({random_domain:.2f}) should be >= "
            f"google.com entropy ({normal:.2f})"
        )

    def test_entropy_value_in_reasonable_range(self):
        e = entropy_for("https://google.com")
        assert 1.0 <= e <= 5.0, f"Entropy {e} seems out of range"


# ════════════════════════════════════════════════════════════════
# 8 — Subdomains
# ════════════════════════════════════════════════════════════════

class TestSubdomains:

    def test_excessive_subdomains_flagged(self):
        deep_url = "https://login.verify.secure.paypal.suspicious.com"
        f = flags_str(deep_url)
        assert "subdomain" in f or heuristic_score(deep_url) > 10, \
            f"Excessive subdomains should be flagged: {flags_for(deep_url)}"

    def test_single_subdomain_not_flagged(self):
        """www.google.com is perfectly normal."""
        f = flags_str("https://www.google.com")
        subdomain_flags = [x for x in flags_for("https://www.google.com")
                           if "subdomain" in x.lower()]
        # single www subdomain should not flag
        assert len(subdomain_flags) == 0


# ════════════════════════════════════════════════════════════════
# 9 — Combined Score Consistency
# ════════════════════════════════════════════════════════════════

class TestHeuristicScoreConsistency:

    def test_more_flags_means_higher_score(self):
        few_flags_score  = heuristic_score("https://google.com")
        many_flags_score = heuristic_score(
            "http://paypal-secure-verify.tk/login/confirm/account"
        )
        assert many_flags_score >= few_flags_score, (
            f"Many flags ({many_flags_score}) should score higher than "
            f"few flags ({few_flags_score})"
        )

    def test_is_suspicious_true_when_high_score(self):
        data = scan_json("http://paypal-verify-account.tk/login")
        h = data["heuristics"]
        if h["heuristic_score"] > 40:
            assert h["is_suspicious"] is True, \
                f"Score {h['heuristic_score']} should set is_suspicious=True"

    def test_google_is_not_suspicious(self, safe_scan):
        assert safe_scan["heuristics"]["is_suspicious"] is False

    def test_flag_count_matches_flags_list_always(self):
        for url in [
            "https://google.com",
            "http://example.tk/login/verify",
            "https://bit.ly/test",
        ]:
            data = scan_json(url)
            h = data["heuristics"]
            assert h["flag_count"] == len(h["flags"]), \
                f"flag_count mismatch for {url}: " \
                f"count={h['flag_count']}, list={len(h['flags'])}"
