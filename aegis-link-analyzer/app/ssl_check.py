"""
Feature 4 — SSL/TLS Certificate Analysis
Aegis Link Analyzer | Phase 1

FIXES in this version:
  - Bug 3: 90-day cert validity is now the industry standard (CA/B Forum 2023).
            Threshold raised — we no longer flag Google Trust Services, DigiCert, etc.
            as suspicious. Free CA flag only adds context, not a large score penalty.
"""

import ssl
import socket
import asyncio
from datetime import datetime
from typing import Dict, List
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor


# ─────────────────────────────────────────────
# REFERENCE DATA
# ─────────────────────────────────────────────

# Free CAs used by phishing sites — still noteworthy but not deeply penalized alone
FREE_CERT_ISSUERS = {
    "let's encrypt": "Let's Encrypt",
    "zerossl": "ZeroSSL",
    "buypass": "Buypass",
}

# Trusted major CAs — never penalize these regardless of cert age
# The CA/Browser Forum mandated ≤90-day certs in 2023; all major CAs comply
TRUSTED_MAJOR_CAS = [
    "google trust services",
    "digicert",
    "comodo",
    "sectigo",
    "globalsign",
    "entrust",
    "verisign",
    "godaddy",
    "amazon",
    "microsoft",
    "apple",
    "cloudflare",
    "geotrust",
    "thawte",
]


# ─────────────────────────────────────────────
# SYNCHRONOUS SSL CHECK
# ─────────────────────────────────────────────

def _run_ssl_check_sync(hostname: str) -> Dict:
    flags: List[str] = []
    score: int = 0
    details: Dict = {}
    issuer_is_trusted_major = False

    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                cert = ssl_sock.getpeercert()
                protocol = ssl_sock.version()
                cipher_name, _, _ = ssl_sock.cipher()
                details["tls_protocol"] = protocol
                details["cipher"] = cipher_name

        # ── Certificate Dates ──────────────────────────────
        not_before_str = cert.get('notBefore', '')
        not_after_str = cert.get('notAfter', '')

        not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        now = datetime.now()

        cert_age_days = (now - not_before).days
        days_until_expiry = (not_after - now).days
        cert_validity_period = (not_after - not_before).days

        details["cert_issued"] = not_before.strftime("%Y-%m-%d")
        details["cert_expires"] = not_after.strftime("%Y-%m-%d")
        details["cert_age_days"] = cert_age_days
        details["days_until_expiry"] = days_until_expiry
        details["validity_period_days"] = cert_validity_period
        details["is_valid"] = True

        # ── Issuer Analysis (do this FIRST so we know if it's a trusted major CA) ─
        issuer = dict(x[0] for x in cert.get('issuer', []))
        issuer_org = issuer.get("organizationName", "Unknown")
        issuer_cn_field = issuer.get("commonName", "")
        details["issuer"] = issuer_org
        details["issuer_cn"] = issuer_cn_field

        issuer_combined = (issuer_org + " " + issuer_cn_field).lower()

        # Check if this is a major trusted CA
        for trusted in TRUSTED_MAJOR_CAS:
            if trusted in issuer_combined:
                issuer_is_trusted_major = True
                details["is_trusted_major_ca"] = True
                break

        if not issuer_is_trusted_major:
            details["is_trusted_major_ca"] = False

        # Check free CAs
        is_free_ca = False
        for free_key, free_name in FREE_CERT_ISSUERS.items():
            if free_key in issuer_combined:
                is_free_ca = True
                details["is_free_cert"] = True
                details["free_ca_name"] = free_name
                # Only flag if NOT also a trusted major CA
                if not issuer_is_trusted_major:
                    flags.append(
                        f"Free certificate authority ({free_name}) — "
                        "phishing sites almost exclusively use free/automated CAs"
                    )
                    score += 10
                break
        else:
            details["is_free_cert"] = False

        # Self-signed detection
        subject = dict(x[0] for x in cert.get('subject', []))
        subject_org = subject.get("organizationName", "")
        if issuer_org and subject_org and issuer_org == subject_org:
            flags.append(
                f"Possible self-signed certificate — "
                f"issuer and subject both show '{issuer_org}'"
            )
            score += 30

        # ── Age-based risk ─────────────────────────────────
        # FIX: Industry moved to 90-day certs in 2023 (CA/B Forum mandate).
        # A cert from Google Trust Services being 31 days old is NOT suspicious.
        # Only flag aggressively when cert is from unknown/free CA AND very new.

        if cert_age_days < 7:
            if not issuer_is_trusted_major:
                flags.append(
                    f"SSL cert is only {cert_age_days} day(s) old (from non-major CA) — "
                    "phishing sites obtain fresh certs right before launching attacks"
                )
                score += 35
            else:
                # Major CA with brand new cert — just informational
                details["cert_age_note"] = f"New cert ({cert_age_days}d) from trusted CA — normal"

        elif cert_age_days < 14:
            if not issuer_is_trusted_major:
                flags.append(
                    f"SSL cert is very new ({cert_age_days} days old, non-major CA) — "
                    "recently issued certs are common in phishing campaigns"
                )
                score += 20

        elif cert_age_days < 30:
            if not issuer_is_trusted_major:
                flags.append(f"SSL cert issued recently ({cert_age_days} days ago, non-major CA)")
                score += 10

        # ── Validity period ────────────────────────────────
        # FIX: 90-day validity is the new normal since CA/B Forum 2023 mandate.
        # Only flag certs shorter than 30 days as suspicious.
        if cert_validity_period <= 30:
            flags.append(
                f"Extremely short certificate validity ({cert_validity_period} days) — "
                "highly unusual even for automated certificates"
            )
            score += 25
        elif cert_validity_period <= 60:
            if not issuer_is_trusted_major:
                flags.append(
                    f"Short certificate validity ({cert_validity_period} days, non-major CA)"
                )
                score += 10
        # 90-day certs: completely normal, no flag at all

        # ── Expiry ────────────────────────────────────────
        if days_until_expiry < 0:
            flags.append("SSL certificate has already EXPIRED — site is untrustworthy")
            score += 50
        elif days_until_expiry < 7:
            flags.append(f"SSL certificate expires in {days_until_expiry} day(s)")
            score += 25
        elif days_until_expiry < 30:
            flags.append(f"SSL certificate expiring in {days_until_expiry} days")
            score += 10

        # ── Common Name / SAN Verification ────────────────
        issued_cn = subject.get("commonName", "")
        details["common_name"] = issued_cn
        san_list = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        details["san_count"] = len(san_list)
        details["san_list"] = san_list[:10]

        if issued_cn:
            if issued_cn.startswith("*."):
                wildcard_base = issued_cn[2:]
                if not hostname.endswith(wildcard_base) and hostname != wildcard_base:
                    if not any(
                        s.startswith("*.") and hostname.endswith(s[2:]) for s in san_list
                    ):
                        flags.append(
                            f"SSL CN mismatch: cert '{issued_cn}' doesn't cover '{hostname}'"
                        )
                        score += 40
            elif issued_cn.lower() != hostname.lower():
                if hostname not in san_list and not any(
                    s.startswith("*.") and hostname.endswith(s[2:]) for s in san_list
                ):
                    flags.append(
                        f"SSL certificate CN mismatch: issued to '{issued_cn}', "
                        f"but connecting to '{hostname}'"
                    )
                    score += 40

        # ── TLS Protocol Version ──────────────────────────
        if protocol and "TLSv1" in protocol and "1.3" not in protocol and "1.2" not in protocol:
            flags.append(f"Outdated TLS protocol: {protocol} — vulnerable to known attacks")
            score += 15
        elif protocol:
            details["tls_note"] = f"Modern protocol: {protocol}"

    except ssl.SSLCertVerificationError as e:
        flags.append("SSL certificate verification FAILED — self-signed, expired, or wrong domain")
        score += 50
        details["is_valid"] = False
        details["ssl_error"] = str(e)

    except ssl.SSLError as e:
        flags.append(f"SSL handshake error: {str(e)}")
        score += 30
        details["is_valid"] = False

    except socket.timeout:
        flags.append("Connection to port 443 timed out")
        score += 15
        details["is_valid"] = False

    except ConnectionRefusedError:
        flags.append("No HTTPS listener on port 443 — site doesn't serve SSL")
        score += 20
        details["is_valid"] = False

    except socket.gaierror:
        flags.append("Cannot resolve hostname for SSL check")
        details["is_valid"] = False

    except Exception as e:
        flags.append(f"SSL check error: {type(e).__name__}: {str(e)}")
        details["is_valid"] = False

    return {
        "flags": flags,
        "ssl_score": min(score, 100),
        "details": details,
        "is_suspicious": min(score, 100) >= 20
    }


# ─────────────────────────────────────────────
# ASYNC WRAPPER
# ─────────────────────────────────────────────

async def run_ssl_check(url: str) -> Dict:
    try:
        parsed = urlparse(url)

        if parsed.scheme != "https":
            return {
                "hostname": parsed.netloc or url,
                "flags": [
                    "URL does not use HTTPS — SSL certificate check skipped. "
                    "All data is transmitted unencrypted."
                ],
                "ssl_score": 20,
                "details": {"is_valid": False, "scheme": parsed.scheme},
                "is_suspicious": True
            }

        hostname = parsed.netloc.split(":")[0].lower()

        if not hostname:
            return {
                "hostname": "unknown",
                "flags": ["Could not extract hostname for SSL check"],
                "ssl_score": 0,
                "details": {},
                "is_suspicious": False
            }

        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = await loop.run_in_executor(pool, _run_ssl_check_sync, hostname)

        result["hostname"] = hostname
        return result

    except Exception as e:
        return {
            "hostname": url,
            "flags": [f"SSL analysis failed: {str(e)}"],
            "ssl_score": 0,
            "details": {},
            "is_suspicious": False
        }
