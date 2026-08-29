"""
Feature 5 — Redirect Chain Tracer
Aegis Link Analyzer | Phase 3

FIXES:
  - Bug: is_www_normalization=True even when hop_count=0 (no redirect happened).
    When a connection fails and both domains are identical, the www-strip check
    incorrectly returns True. Fixed: normalization flag only fires when
    hop_count > 0 AND there was an actual domain change.
"""

import httpx
import asyncio
from typing import Dict, List
from urllib.parse import urlparse, urljoin

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "short.io", "tiny.cc", "shorturl.at", "cutt.ly", "rb.gy",
    "bl.ink", "snip.ly", "lnkd.in", "adf.ly", "bc.vc", "x.co",
    "su.pr", "ff.im", "j.mp", "dlvr.it", "ift.tt", "soo.gd"
}

SUSPICIOUS_REDIRECT_PATHS = [
    "/track", "/click", "/redirect", "/go/", "/out/", "/link/",
    "/r/", "/ref/", "/forward/", "/l/", "?url=", "?redirect=",
    "?return=", "?next=", "?destination=", "?goto="
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def _strip_www(domain: str) -> str:
    return domain[4:] if domain.startswith("www.") else domain


def _is_www_normalization(domain_a: str, domain_b: str, hop_count: int) -> bool:
    """
    FIX: Added hop_count guard.
    Returns True ONLY when:
      1. An actual redirect occurred (hop_count > 0)
      2. The domains are different (otherwise it's not a change at all)
      3. The ONLY difference is the www. prefix

    Previously returned True when hop_count=0 because both domains were identical
    and stripping www from two identical strings always matches.
    """
    if hop_count == 0:
        return False  # No redirect happened — can't be normalization
    if domain_a == domain_b:
        return False  # Domains identical — no change at all (not normalization)
    return _strip_www(domain_a.lower()) == _strip_www(domain_b.lower())


async def trace_redirects(url: str, max_hops: int = 10) -> Dict:
    """Traces the full HTTP redirect chain for a URL."""
    flags: List[str] = []
    score: int = 0
    hops: List[Dict] = []
    shorteners_found: List[str] = []
    suspicious_paths_found: List[str] = []
    current_url = url
    visited_urls = set()

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(10.0, connect=5.0),
            headers=HEADERS,
            verify=False,
        ) as client:

            for hop_num in range(max_hops):
                if current_url in visited_urls:
                    flags.append(f"Redirect loop detected at hop {hop_num + 1}")
                    score += 20
                    break
                visited_urls.add(current_url)

                parsed = urlparse(current_url)
                current_domain = parsed.netloc.lower()
                clean_domain = current_domain.split(":")[0]

                if clean_domain in URL_SHORTENERS:
                    shorteners_found.append(clean_domain)

                for sus_path in SUSPICIOUS_REDIRECT_PATHS:
                    if sus_path in current_url.lower():
                        suspicious_paths_found.append(sus_path)
                        break

                try:
                    response = await client.get(current_url)
                    hops.append({
                        "hop": hop_num + 1,
                        "url": current_url,
                        "domain": current_domain,
                        "status_code": response.status_code,
                        "is_shortener": clean_domain in URL_SHORTENERS,
                    })

                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location", "").strip()
                        if not location:
                            flags.append(f"Redirect at hop {hop_num + 1} has no Location header")
                            break
                        if location.startswith("/"):
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"
                        elif not location.startswith(("http://", "https://")):
                            location = urljoin(current_url, location)
                        current_url = location
                    else:
                        break

                except httpx.TimeoutException:
                    flags.append(f"Request timed out at hop {hop_num + 1}: {current_url}")
                    break
                except httpx.ConnectError:
                    flags.append(f"Connection failed at hop {hop_num + 1}: {current_url}")
                    break
                except httpx.TooManyRedirects:
                    flags.append("Too many redirects — server-side redirect loop")
                    score += 30
                    break
                except Exception as e:
                    flags.append(f"Error at hop {hop_num + 1}: {type(e).__name__}: {str(e)}")
                    break

    except Exception as e:
        flags.append(f"Redirect tracer initialization failed: {str(e)}")

    # ── Post-trace analysis ────────────────────────────
    hop_count = len(hops)
    final_url = hops[-1]["url"] if hops else url
    final_domain = urlparse(final_url).netloc.lower()
    original_domain = urlparse(url).netloc.lower()

    if hop_count == 0:
        flags.append("Could not follow any redirects from this URL")
    elif hop_count > 5:
        flags.append(f"Very long redirect chain: {hop_count} hops")
        score += min(hop_count * 6, 35)
    elif hop_count > 3:
        flags.append(f"Long redirect chain: {hop_count} hops")
        score += min(hop_count * 4, 20)

    unique_shorteners = list(set(shorteners_found))
    if unique_shorteners:
        flags.append(
            f"URL shortener(s) in redirect chain: {', '.join(unique_shorteners)}. "
            "Shorteners mask the true destination — common in phishing"
        )
        score += 20

    destination_changed = (
        original_domain != final_domain
        and bool(original_domain)
        and bool(final_domain)
    )

    # FIX: Pass hop_count to normalization check
    is_www_only = _is_www_normalization(original_domain, final_domain, hop_count)

    if destination_changed and not is_www_only:
        flags.append(
            f"Domain changed during redirect: '{original_domain}' → '{final_domain}'"
        )
        score += 15
    # If is_www_only=True: no flag, no score, just informational field in response

    if suspicious_paths_found:
        flags.append(f"Suspicious redirect paths: {', '.join(set(suspicious_paths_found))}")
        score += 10

    if url.startswith("https://") and final_url.startswith("http://"):
        flags.append(
            "Protocol downgrade: HTTPS → HTTP during redirect — "
            "connection becomes unencrypted mid-chain"
        )
        score += 25

    final_status = hops[-1]["status_code"] if hops else None
    if final_status == 404:
        flags.append("Final destination returns 404 — dead phishing link")
        score += 10
    elif final_status and final_status >= 500:
        flags.append(f"Final destination returned server error {final_status}")
        score += 5

    return {
        "original_url": url,
        "final_url": final_url,
        "hop_count": hop_count,
        "hops": hops,
        "shorteners_found": unique_shorteners,
        "destination_changed": destination_changed,
        "is_www_normalization": is_www_only,
        "original_domain": original_domain,
        "final_domain": final_domain,
        "final_status_code": final_status,
        "suspicious_paths": list(set(suspicious_paths_found)),
        "flags": flags,
        "redirect_score": min(score, 100),
        "is_suspicious": min(score, 100) >= 15
    }
