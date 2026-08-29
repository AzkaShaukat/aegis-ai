"""
Feature 3 — DNS Intelligence Layer
Aegis Link Analyzer | Phase 1

Performs deep DNS analysis to detect suspicious infrastructure patterns.
Phishing sites often fail basic DNS health checks (missing MX, no SPF, etc.)
Uses dnspython — no API key required.
"""

import asyncio
import dns.resolver
import dns.reversename
import dns.exception
from typing import Dict, List, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor


# ─────────────────────────────────────────────
# SYNCHRONOUS DNS CHECKS
# (Blocking — run in thread pool)
# ─────────────────────────────────────────────

def _run_dns_checks_sync(hostname: str) -> Dict:
    """
    Performs all DNS record checks for a given hostname.
    This is synchronous because dnspython's resolver is blocking.
    """
    flags: List[str] = []
    score: int = 0
    details: Dict = {}

    # ── Check 1: A Record (Does domain resolve?) ──────
    ip_addresses: List[str] = []
    try:
        a_answers = dns.resolver.resolve(hostname, 'A', lifetime=8.0)
        ip_addresses = [str(r) for r in a_answers]
        details["ip_addresses"] = ip_addresses
        details["resolves"] = True
    except dns.resolver.NXDOMAIN:
        flags.append(
            "Domain does not exist (NXDOMAIN) — "
            "may be a dead phishing domain or a scam link"
        )
        score += 40
        details["resolves"] = False
        details["ip_addresses"] = []
    except dns.resolver.NoAnswer:
        flags.append("Domain exists but has no A record — unable to resolve to an IP")
        score += 25
        details["resolves"] = False
        details["ip_addresses"] = []
    except dns.exception.Timeout:
        flags.append("DNS resolution timed out — server may be down or blocking queries")
        score += 15
        details["resolves"] = False
        details["ip_addresses"] = []
    except Exception as e:
        flags.append(f"DNS A-record lookup error: {str(e)}")
        details["resolves"] = False
        details["ip_addresses"] = []

    # ── Check 2: MX Records (Email server setup) ──────
    # Legitimate businesses always configure email; phishing sites often skip it
    try:
        mx_answers = dns.resolver.resolve(hostname, 'MX', lifetime=8.0)
        mx_records = [str(r.exchange).rstrip(".") for r in mx_answers]
        details["mx_records"] = mx_records
        details["has_mx"] = True
    except Exception:
        flags.append(
            "No MX (mail) records found — "
            "legitimate organizations always configure email servers"
        )
        score += 15
        details["mx_records"] = []
        details["has_mx"] = False

    # ── Check 3: TXT Records (SPF/DKIM security) ──────
    # SPF prevents email spoofing — phishing domains often skip it
    try:
        txt_answers = dns.resolver.resolve(hostname, 'TXT', lifetime=8.0)
        txt_records = [str(r).strip('"') for r in txt_answers]
        details["txt_records"] = txt_records

        has_spf = any("v=spf1" in r.lower() for r in txt_records)
        has_dmarc = any("v=dmarc1" in r.lower() for r in txt_records)

        details["has_spf"] = has_spf
        details["has_dmarc"] = has_dmarc

        if not has_spf:
            flags.append(
                "No SPF record — domain hasn't configured email authentication "
                "(phishing sites commonly skip this)"
            )
            score += 10

        if not has_dmarc:
            # DMARC is less universal, so smaller penalty
            score += 5

    except Exception:
        details["txt_records"] = []
        details["has_spf"] = False
        details["has_dmarc"] = False
        score += 10

    # ── Check 4: CNAME Chain Depth ────────────────────
    # Deep CNAME chains can be used to hide final destinations
    try:
        cname_depth = 0
        current = hostname
        visited_cnames = set()

        while current not in visited_cnames and cname_depth < 10:
            visited_cnames.add(current)
            try:
                cname_answers = dns.resolver.resolve(current, 'CNAME', lifetime=5.0)
                current = str(cname_answers[0].target).rstrip(".")
                cname_depth += 1
            except Exception:
                break

        details["cname_depth"] = cname_depth
        details["cname_chain"] = list(visited_cnames)

        if cname_depth > 3:
            flags.append(
                f"Deep CNAME redirect chain ({cname_depth} hops) — "
                "unusual depth can indicate infrastructure obfuscation"
            )
            score += 20
        elif cname_depth > 1:
            details["cname_note"] = f"CNAME chain: {cname_depth} hops (acceptable)"

    except Exception as e:
        details["cname_depth"] = 0
        details["cname_error"] = str(e)

    # ── Check 5: Reverse DNS (PTR) Consistency ────────
    # If the IP's reverse DNS doesn't match the domain, it's suspicious
    if ip_addresses:
        try:
            primary_ip = ip_addresses[0]
            rev_name = dns.reversename.from_address(primary_ip)
            ptr_answers = dns.resolver.resolve(rev_name, 'PTR', lifetime=8.0)
            ptr_hostname = str(ptr_answers[0]).rstrip(".")
            details["reverse_dns"] = ptr_hostname
            details["primary_ip"] = primary_ip

            # Check if PTR record relates to our domain at all
            if hostname not in ptr_hostname and not ptr_hostname.endswith(hostname):
                flags.append(
                    f"Reverse DNS mismatch: IP {primary_ip} resolves back to "
                    f"'{ptr_hostname}', not '{hostname}'"
                )
                score += 10

        except dns.resolver.NXDOMAIN:
            details["reverse_dns"] = None
            flags.append(f"No reverse DNS (PTR) record for IP {ip_addresses[0] if ip_addresses else 'N/A'}")
            score += 5
        except Exception:
            details["reverse_dns"] = None

    # ── Check 6: NS Record Anomalies ──────────────────
    try:
        ns_answers = dns.resolver.resolve(hostname, 'NS', lifetime=8.0)
        ns_records = [str(r).rstrip(".") for r in ns_answers]
        details["nameservers"] = ns_records

        # Single nameserver is unusual and risky (no redundancy)
        if len(ns_records) == 1:
            flags.append(
                "Only one nameserver configured — "
                "legitimate domains use at least 2 for redundancy"
            )
            score += 10

        # Free DNS providers commonly used for throwaway domains
        free_dns_providers = ["afraid.org", "changeip.com", "no-ip.com", "dyndns"]
        for provider in free_dns_providers:
            if any(provider in ns for ns in ns_records):
                flags.append(
                    f"Free/dynamic DNS provider detected in nameservers ({provider}) — "
                    "commonly used for throwaway phishing domains"
                )
                score += 15
                break

    except Exception:
        details["nameservers"] = []
        flags.append("Could not retrieve NS records for domain")
        score += 5

    final_score = min(score, 100)

    return {
        "hostname": hostname,
        "flags": flags,
        "dns_score": final_score,
        "details": details,
        "is_suspicious": final_score >= 20
    }


# ─────────────────────────────────────────────
# ASYNC WRAPPER
# ─────────────────────────────────────────────

async def run_dns_check(url: str) -> Dict:
    """
    Async DNS intelligence check for a given URL.

    Returns:
        dict with:
          - hostname: extracted hostname
          - flags: list of warning strings
          - dns_score: 0-100 risk score
          - details: raw DNS data (IPs, MX, NS, etc.)
          - is_suspicious: True if score >= 20
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0].lower()

        # Strip www — we want the root domain's DNS health
        if hostname.startswith("www."):
            hostname = hostname[4:]

        if not hostname:
            return {
                "hostname": "unknown",
                "flags": ["Could not extract hostname from URL"],
                "dns_score": 10,
                "details": {},
                "is_suspicious": False
            }

        # Run all blocking DNS lookups in a thread pool
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = await loop.run_in_executor(pool, _run_dns_checks_sync, hostname)

        return result

    except Exception as e:
        return {
            "hostname": url,
            "flags": [f"DNS intelligence check failed: {str(e)}"],
            "dns_score": 0,
            "details": {},
            "is_suspicious": False
        }
