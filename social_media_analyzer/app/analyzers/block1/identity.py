"""
Block 1 — Identity & Profile Foundation
All checks consolidated in one file.
"""
import re, math, hashlib, asyncio, logging
from typing import Any, Dict, List, Optional, Tuple
import httpx

from app.config   import get_settings
from app.models   import (
    UsernameResult, PhotoResult, AccountResult,
    PhoneResult, EmailResult,
)
from data.patterns import (
    RANDOM_USERNAME_RE, LEET_IMPERSONATION_RE,
    LOOKALIKE_BRANDS, PHONE_RE, EMOJI_RE,
)

logger   = logging.getLogger(__name__)
settings = get_settings()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


# ─────────────────────────────────────────────────────────────────────────────
#  USERNAME ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
def _entropy(s: str) -> float:
    if not s: return 0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def analyze_username(username: str) -> UsernameResult:
    r = UsernameResult(username=username)
    pts, flags = 0, []

    # Username entropy
    ent = _entropy(username)
    r.entropy_score = round(ent, 3)
    if ent > 3.5:
        pts += 15; flags.append(f"high_entropy_username:{ent:.2f}")
    elif ent > 3.0:
        pts += 8;  flags.append(f"medium_entropy_username:{ent:.2f}")

    # Random pattern (letters + 5+ digits)
    if RANDOM_USERNAME_RE.match(username):
        r.random_pattern = True
        pts += 12; flags.append("random_generated_username")

    # Leet-speak impersonation
    if LEET_IMPERSONATION_RE.search(username):
        r.leet_impersonation = True
        pts += 20; flags.append("leet_impersonation_detected")

    # Excessive digits
    digits = sum(c.isdigit() for c in username)
    if digits > 4 and len(username) > 0 and digits / len(username) > 0.4:
        r.excessive_digits = True
        pts += 8; flags.append(f"excessive_digits:{digits}")

    # Brand impersonation — also check leet-normalized version (0→o, 1→l/i, 3→e, etc.)
    LEET_MAP = str.maketrans("01345678@", "oleasstba")
    u_lower      = username.lower().replace("_", "").replace(".", "").replace("-", "")
    u_leet_norm  = u_lower.translate(LEET_MAP)
    for brand in LOOKALIKE_BRANDS:
        if (brand in u_lower or brand in u_leet_norm) and u_lower != brand:
            r.impersonates_brand = brand
            pts += 25; flags.append(f"brand_impersonation:{brand}")
            break

    # Suspiciously long with many underscores
    if username.count("_") >= 3 or username.count(".") >= 3:
        pts += 5; flags.append("excessive_separators_in_username")

    r.suspicion_score = pts
    r.flags = flags
    r.checks["username_analysis"] = {
        "entropy": ent, "random": r.random_pattern,
        "leet": r.leet_impersonation, "digits": digits,
    }
    return r.finalize()


# ─────────────────────────────────────────────────────────────────────────────
#  ACCOUNT META ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
def analyze_account(
    followers:      Optional[int],
    following:      Optional[int],
    posts_count:    Optional[int],
    account_age_days: Optional[int],
    bio:            Optional[str],
    has_profile_pic: bool = True,
    location_set:   bool = False,
    link_set:       bool = False,
    is_verified:    bool = False,
) -> AccountResult:
    r = AccountResult()
    pts, flags = 0, []

    # New account
    if account_age_days is not None:
        r.account_age_days = account_age_days
        if account_age_days < 7:
            r.new_account_signal = True
            pts += 20; flags.append(f"very_new_account:{account_age_days}days")
        elif account_age_days < 30:
            r.new_account_signal = True
            pts += 10; flags.append(f"new_account:{account_age_days}days")

    # F/F ratio
    if followers is not None and following is not None:
        r.followers = followers
        r.following  = following
        ratio = followers / max(following, 1)
        r.ff_ratio = round(ratio, 3)
        if followers > 10000 and following < 100:
            r.high_ff_ratio_signal = True
            pts += 12; flags.append(f"suspicious_ff_ratio:{ratio:.1f}")

    # Empty bio
    if not bio or len(bio.strip()) < 5:
        r.bio_empty = True
        pts += 8; flags.append("empty_bio")

    # No profile picture
    if not has_profile_pic:
        r.default_pic = True
        pts += 10; flags.append("no_profile_picture")

    # Posts per day
    if posts_count is not None and account_age_days and account_age_days > 0:
        ppd = posts_count / account_age_days
        r.posts_per_day = round(ppd, 2)
        if ppd > 50:
            pts += 15; flags.append(f"extreme_posting_rate:{ppd:.0f}posts/day")
        elif ppd > 20:
            pts += 8; flags.append(f"high_posting_rate:{ppd:.0f}posts/day")

    r.posts_count  = posts_count
    r.location_set = location_set
    r.link_set     = link_set
    r.verified     = is_verified
    r.suspicion_score = pts
    r.flags = flags
    r.checks["account"] = {
        "age_days": account_age_days, "ff_ratio": r.ff_ratio,
        "posts_per_day": r.posts_per_day,
    }
    return r.finalize()


# ─────────────────────────────────────────────────────────────────────────────
#  PHONE ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
async def analyze_phone(phone: str) -> PhoneResult:
    r = PhoneResult(phone=phone)
    pts, flags = 0, []

    # IPQS check (optional)
    if settings.ipqs_api_key:
        try:
            encoded = httpx.URL("").copy_with(params={"phone": phone}).params
            async with httpx.AsyncClient(timeout=10) as c:
                resp = await c.get(
                    f"https://www.ipqualityscore.com/api/json/phone/{settings.ipqs_api_key}/{phone}"
                )
            if resp.status_code == 200:
                d = resp.json()
                r.valid       = d.get("valid", False)
                r.carrier     = d.get("carrier", "")
                r.line_type   = d.get("line_type", "")
                r.country     = d.get("country", "")
                r.is_voip     = d.get("VOIP", False)
                r.is_disposable = d.get("disposable", False)
                r.ipqs_fraud_score = d.get("fraud_score", 0)
                r.recent_abuse = d.get("recent_abuse", False)
                score = d.get("fraud_score", 0)
                if score >= 85:
                    pts += 20; flags.append(f"ipqs_high_fraud_phone:{score}")
                elif score >= 60:
                    pts += 10
                if r.is_voip:
                    pts += 10; flags.append("voip_number")
                if r.is_disposable:
                    pts += 15; flags.append("disposable_phone_number")
                if r.recent_abuse:
                    pts += 8; flags.append("phone_recent_abuse")
        except Exception as e:
            logger.debug(f"[phone:ipqs] {e}")
            r.checks["ipqs"] = {"error": str(e)}
    else:
        # Heuristic only
        r.valid = bool(PHONE_RE.search(phone))
        r.checks["ipqs"] = {"available": False, "note": "Set IPQS_API_KEY for full check"}
        if not r.valid:
            pts += 5; flags.append("invalid_phone_format")

    r.suspicion_score = pts
    r.flags = flags
    return r.finalize()


# ─────────────────────────────────────────────────────────────────────────────
#  EMAIL ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "throwaway.email", "yopmail.com", "sharklasers.com", "guerrillamailblock.com",
    "fakeinbox.com", "maildrop.cc", "trashmail.com", "tempinbox.com",
    "dispostable.com", "spamgourmet.com", "spamgourmet.org",
}
FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "icloud.com", "protonmail.com", "aol.com", "mail.com",
}
ROLE_PREFIXES = {
    "admin", "info", "support", "sales", "help", "contact",
    "noreply", "no-reply", "postmaster", "webmaster",
}


async def analyze_email(email: str) -> EmailResult:
    r = EmailResult(email=email)
    pts, flags = 0, []

    # Format check
    email_re = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    r.valid_format = bool(email_re.match(email))
    if not r.valid_format:
        pts += 10; flags.append("invalid_email_format")
        r.suspicion_score = pts; r.flags = flags
        return r.finalize()

    local, domain = email.rsplit("@", 1)
    domain = domain.lower()

    r.is_disposable    = domain in DISPOSABLE_DOMAINS
    r.is_free_provider = domain in FREE_PROVIDERS
    r.is_role_account  = local.lower().split("+")[0] in ROLE_PREFIXES

    if r.is_disposable:
        pts += 25; flags.append(f"disposable_email_domain:{domain}")
    if r.is_role_account:
        pts += 5;  flags.append("role_email_account")

    # MX check
    try:
        import dns.resolver
        dns.resolver.resolve(domain, "MX", lifetime=5)
        r.valid_mx = True
    except Exception:
        r.valid_mx = False
        pts += 8; flags.append("no_mx_record")

    # IPQS
    if settings.ipqs_api_key:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                resp = await c.get(
                    f"https://www.ipqualityscore.com/api/json/email/{settings.ipqs_api_key}/{email}"
                )
            if resp.status_code == 200:
                d = resp.json()
                r.is_disposable    = r.is_disposable or d.get("disposable", False)
                r.ipqs_fraud_score = d.get("fraud_score", 0)
                r.leaked           = d.get("leaked", False)
                if d.get("fraud_score", 0) >= 80:
                    pts += 15; flags.append(f"ipqs_high_fraud_email:{d['fraud_score']}")
                if r.leaked:
                    pts += 10; flags.append("email_found_in_breach")
        except Exception as e:
            logger.debug(f"[email:ipqs] {e}")

    r.suspicion_score = pts
    r.flags = flags
    r.checks["email"] = {
        "domain": domain, "mx": r.valid_mx,
        "disposable": r.is_disposable, "free": r.is_free_provider,
    }
    return r.finalize()
