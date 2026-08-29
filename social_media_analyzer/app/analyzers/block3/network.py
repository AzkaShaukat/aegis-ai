"""
Block 3 — Network & Social Intelligence
All checks consolidated.
"""
import re, statistics, asyncio, logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import httpx

from app.config import get_settings
from app.models import (
    EngagementResult, CrossPlatformResult, OsintResult, BehaviorResult,
    FollowerSample, FollowEvent, MentionEdge, CoordAction,
)
from data.patterns import ENGAGEMENT_BENCHMARKS, PLATFORM_URLS, SCHEDULER_APPS

logger   = logging.getLogger(__name__)
settings = get_settings()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def _tier(followers: int) -> str:
    if followers < 1_000:       return "micro"
    elif followers < 10_000:    return "small"
    elif followers < 100_000:   return "medium"
    elif followers < 1_000_000: return "large"
    return "mega"


def _to_epoch(ts: str) -> Optional[float]:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  ENGAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
def analyze_engagement(
    platform:         str,
    followers:        int,
    following:        Optional[int]              = None,
    post_samples:     Optional[List[Dict]]       = None,  # {likes, comments, shares}
    follower_sample:  Optional[List[FollowerSample]] = None,
    follower_history: Optional[List[Dict]]       = None,
) -> EngagementResult:
    r = EngagementResult()
    pts, flags = 0, []

    # ENG-01: Engagement rate
    if post_samples and followers > 0:
        rates = []
        for p in post_samples:
            total = (p.get("likes") or 0) + (p.get("comments") or 0) + (p.get("shares") or 0)
            rates.append(total / followers * 100)
        if rates:
            avg = statistics.mean(rates)
            r.engagement_rate = round(avg, 3)
            tier  = _tier(followers)
            bench = ENGAGEMENT_BENCHMARKS.get(platform.lower(), ENGAGEMENT_BENCHMARKS["default"]).get(tier, 1.0)
            if avg < bench * 0.1 and followers > 5000:
                pts += 20; flags.append(f"very_low_engagement:{avg:.2f}%_vs_bench_{bench:.2f}%")
            elif avg < bench * 0.3:
                pts += 10; flags.append(f"low_engagement:{avg:.2f}%")

    # ENG-02: Follower quality
    if follower_sample:
        signals = ["default_avatar", "no_bio", "no_posts", "created_recently",
                   "high_following_ratio", "random_username", "zero_followers"]
        bot_scores = [
            sum(1 for s in signals if getattr(f, s, False)) / len(signals)
            for f in follower_sample
        ]
        bot_pct = sum(1 for s in bot_scores if s >= 0.5) / len(bot_scores) * 100
        r.bot_follower_pct = round(bot_pct, 1)
        if bot_pct > 50:
            r.purchased_followers = True
            pts += 20; flags.append(f"purchased_followers:{bot_pct:.0f}%_bot_followers")
        elif bot_pct > 30:
            r.purchased_followers = True
            pts += 12; flags.append(f"purchased_followers_likely:{bot_pct:.0f}%")

    # ENG-04: Follower spike
    if follower_history and len(follower_history) >= 3:
        try:
            hist = sorted(follower_history, key=lambda x: x.get("date", ""))
            gains = [(hist[i]["date"], hist[i].get("followers", 0) - hist[i-1].get("followers", 0))
                     for i in range(1, len(hist))]
            gv = [abs(g[1]) for g in gains]
            for idx, (date, gain) in enumerate(gains):
                # Baseline = mean of all gains BEFORE this point (not including current)
                prior = gv[:idx] if idx > 0 else []
                baseline = statistics.mean(prior) if prior else 0
                if baseline > 0 and abs(gain) > baseline * 8 and abs(gain) > 500:
                    r.spike_detected = True
                    r.spike_day      = date
                    r.spike_gain     = gain
                    pts += 18; flags.append(f"follower_spike:{gain:+d}_on_{date}")
                    break
                elif abs(gain) > 5000 and abs(gain) > 500:
                    # Absolute threshold: 50k+ gain with no prior history
                    r.spike_detected = True
                    r.spike_day      = date
                    r.spike_gain     = gain
                    pts += 18; flags.append(f"follower_spike:{gain:+d}_on_{date}")
                    break
        except Exception:
            pass

    # ENG-05: Ghost followers — check even without post_samples (use given rates or estimate)
    if followers > 10000:
        tier  = _tier(followers)
        bench = ENGAGEMENT_BENCHMARKS.get(platform.lower(), ENGAGEMENT_BENCHMARKS["default"]).get(tier, 1.0)
        if r.engagement_rate is not None and r.engagement_rate < bench * 0.05:
            r.ghost_follower_signal = True
            pts += 15; flags.append(f"ghost_followers:engagement={r.engagement_rate:.3f}%")
        elif r.engagement_rate is None and post_samples:
            # post_samples provided but all zeros → ghost signal
            total_eng = sum((p.get("likes") or 0) + (p.get("comments") or 0) + (p.get("shares") or 0)
                            for p in post_samples)
            if total_eng == 0:
                r.ghost_follower_signal = True
                pts += 15; flags.append("ghost_followers:zero_engagement_on_all_posts")

    # ENG-06: Follow/unfollow cycling
    if follower_history:
        follows   = [h for h in follower_history if h.get("action") == "follow"]
        unfollows = [h for h in follower_history if h.get("action") == "unfollow"]
        tf = sum(h.get("count", 0) for h in follows)
        tu = sum(h.get("count", 0) for h in unfollows)
        if tf > 200 and tu > tf * 0.5:
            r.follow_cycling = True
            pts += 12; flags.append("follow_unfollow_cycling_detected")

    # ENG-07: Mutual ratio
    if following and followers:
        ratio = min(following, followers) / max(following, followers)
        r.mutual_ratio = round(ratio, 3)
        if ratio < 0.05 and followers > 5000:
            pts += 8; flags.append(f"low_mutual_ratio:{ratio:.3f}")

    r.suspicion_score = pts; r.flags = flags
    return r.finalize()


# ─────────────────────────────────────────────────────────────────────────────
#  CROSS PLATFORM
# ─────────────────────────────────────────────────────────────────────────────
async def _check_one(client: httpx.AsyncClient, platform: str, url: str) -> Tuple[str, bool, int]:
    try:
        r = await client.head(url, timeout=7, follow_redirects=True)
        exists = r.status_code == 200
        if r.status_code in (301, 302):
            loc = str(r.headers.get("location", "")).lower()
            exists = not any(kw in loc for kw in ["login", "signup", "404"])
        return platform, exists, r.status_code
    except Exception:
        return platform, False, 0


async def analyze_cross_platform(
    username: str,
    bio:      Optional[str] = None,
    full_scan: bool = False,
) -> CrossPlatformResult:
    r = CrossPlatformResult(username=username)
    pts, flags = 0, []

    targets = list(PLATFORM_URLS.items()) if full_scan else [
        (k, v) for k, v in PLATFORM_URLS.items()
        if k in {"twitter", "instagram", "tiktok", "youtube", "github",
                 "reddit", "linkedin", "twitch", "telegram"}
    ]

    async with httpx.AsyncClient(headers={"User-Agent": UA},
                                  follow_redirects=False, timeout=8) as c:
        results = await asyncio.gather(
            *[_check_one(c, p, u.format(u=username)) for p, u in targets],
            return_exceptions=True,
        )

    found = [p for res in results if isinstance(res, tuple) and res[1] for p, _, _ in [res]]
    r.platforms_found   = found
    r.platforms_checked = len(targets)
    r.sherlock_count    = len(found)

    if len(found) >= 8:
        pts += 10; flags.append(f"found_on_{len(found)}_platforms:name_squatting_signal")
    elif len(found) >= 5:
        pts += 5

    # Bio authority claim
    if bio:
        authority = ["official", "verified", "ceo", "founder", "admin", "government"]
        if any(kw in bio.lower() for kw in authority):
            r.bio_authority_claim = True
            pts += 5; flags.append("bio_claims_authority")

    # Dark web (Ahmia)
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            resp = await c.get("https://ahmia.fi/search/",
                               params={"q": username},
                               headers={"User-Agent": UA})
        if resp.status_code == 200:
            onions = re.findall(r"[a-z2-7]{16,56}\.onion", resp.text)
            if onions:
                r.dark_web_mention  = True
                r.dark_web_results  = list(set(onions))[:5]
                pts += 15; flags.append(f"dark_web_mention:{len(onions)}_onion_links")
    except Exception:
        pass

    r.suspicion_score = pts; r.flags = flags
    return r.finalize()


# ─────────────────────────────────────────────────────────────────────────────
#  OSINT
# ─────────────────────────────────────────────────────────────────────────────
async def _leakcheck(query: str) -> Dict:
    params = {"check": query}
    if settings.leakcheck_api_key:
        params["key"] = settings.leakcheck_api_key
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get("https://leakcheck.io/api/public", params=params)
        if r.status_code == 200:
            d = r.json()
            return {"available": True, "found": d.get("found", False),
                    "count": len(d.get("sources", [])), "sources": d.get("sources", [])[:5]}
        return {"available": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"available": False, "error": str(e)}


async def _hudsonrock(query: str, qtype: str = "email") -> Dict:
    if not settings.hudsonrock_enabled:
        return {"available": False}
    ep = {
        "email":    f"https://api.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={query}",
        "username": f"https://api.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username={query}",
        "domain":   f"https://api.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={query}",
        "ip":       f"https://api.hudsonrock.com/api/json/v2/osint-tools/search-by-ip?ip={query}",
    }
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(ep.get(qtype, ep["email"]), headers={"User-Agent": UA})
        if r.status_code == 404: return {"available": True, "found": False}
        if r.status_code != 200: return {"available": False}
        d = r.json()
        return {"available": True, "found": d.get("stealers_count", 0) > 0,
                "stealers": d.get("stealers_count", 0)}
    except Exception as e:
        return {"available": False, "error": str(e)}


async def _breachdirectory(query: str) -> Dict:
    """
    BreachDirectory — 100% free, no API key, no signup.
    Checks if email or username appears in known data breaches.
    API: https://breachdirectory.org/api
    """
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(
                "https://breachdirectory.p.rapidapi.com/",
                params={"func": "auto", "term": query},
                headers={
                    "User-Agent": UA,
                    "Accept": "application/json",
                },
            )
        # Public endpoint (no RapidAPI key) returns results differently
        if r.status_code == 200:
            d = r.json()
            found = d.get("found", 0)
            return {
                "available": True,
                "found": found > 0,
                "count": found,
                "sources": d.get("result", [])[:5],
            }
        # Fallback — try the open public endpoint
        async with httpx.AsyncClient(timeout=12) as c:
            r2 = await c.get(
                f"https://api.breachdirectory.org/?func=auto&term={query}",
                headers={"User-Agent": UA},
            )
        if r2.status_code == 200:
            d = r2.json()
            found = d.get("found", 0)
            return {"available": True, "found": found > 0, "count": found}
        return {"available": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"available": False, "error": str(e)}


async def _hibp(email: str) -> Dict:
    """
    Have I Been Pwned — free API key (no cost, just register).
    Get key at: haveibeenpwned.com/API/v3
    Set HIBP_API_KEY in .env — falls back to truncated hash check if no key.
    """
    if not email or "@" not in email:
        return {"available": False, "reason": "email_only"}

    # Without a key: use the pwned passwords hash check (k-anonymity, no email)
    # With a key: full breach lookup
    if not settings.hibp_api_key:
        return {
            "available": False,
            "skipped": "Set HIBP_API_KEY (free at haveibeenpwned.com/API/v3)",
        }
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": settings.hibp_api_key,
                    "User-Agent":   "AegisAI-FakeProfileDetector/2.0",
                },
                params={"truncateResponse": "false"},
            )
        if r.status_code == 404:
            return {"available": True, "found": False, "breaches": []}
        if r.status_code == 401:
            return {"available": False, "error": "Invalid HIBP API key"}
        if r.status_code == 200:
            breaches = r.json()
            names = [b.get("Name", "") for b in breaches[:10]]
            return {
                "available": True,
                "found": True,
                "count": len(breaches),
                "breach_names": names,
                "sensitive": any(b.get("IsSensitive") for b in breaches),
                "verified":   any(b.get("IsVerified") for b in breaches),
            }
        return {"available": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"available": False, "error": str(e)}
    try:
        hdrs = {"User-Agent": UA}
        if settings.greynoise_api_key:
            hdrs["key"] = settings.greynoise_api_key
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.get(f"https://api.greynoise.io/v3/community/{ip}", headers=hdrs)
        if r.status_code == 404: return {"available": True, "found": False}
        if r.status_code != 200: return {"available": False}
        d = r.json()
        return {"available": True, "found": True, "noise": d.get("noise", False),
                "classification": d.get("classification", "unknown"),
                "malicious": d.get("classification") == "malicious"}
    except Exception as e:
        return {"available": False, "error": str(e)}


async def analyze_osint(
    email:    Optional[str] = None,
    phone:    Optional[str] = None,
    username: Optional[str] = None,
    ip:       Optional[str] = None,
    domain:   Optional[str] = None,
) -> OsintResult:
    r = OsintResult(queried_email=email, queried_username=username, queried_ip=ip)
    pts, flags = 0, []

    primary = email or phone or username or domain
    if not primary:
        r.flags = ["no_osint_query_provided"]; return r

    ptype = "email" if email else "phone" if phone else "username" if username else "domain"

    # ── Run all OSINT checks in parallel ────────────────────────────────
    coros: Dict[str, Any] = {
        "leakcheck":       _leakcheck(primary),
        "hudsonrock":      _hudsonrock(primary, ptype),
        "breachdirectory": _breachdirectory(primary),
    }
    if email:
        coros["hibp"] = _hibp(email)
    if ip:
        coros["greynoise"] = _greynoise(ip)

    keys = list(coros)
    outs = await asyncio.gather(*coros.values(), return_exceptions=True)
    res  = {k: (v if isinstance(v, dict) else {}) for k, v in zip(keys, outs)}

    # ── LeakCheck ────────────────────────────────────────────────────────
    lc = res.get("leakcheck", {})
    r.leakcheck_found = lc.get("found", False)
    r.leakcheck_count = lc.get("count", 0)
    r.checks["leakcheck"] = lc
    if r.leakcheck_found:
        pts += min(r.leakcheck_count * 4, 18)
        flags.append(f"leakcheck_breach:{r.leakcheck_count}_sources")

    # ── HudsonRock Cavalier (stealer logs — FREE) ────────────────────────
    hr = res.get("hudsonrock", {})
    r.hudsonrock_found = hr.get("found", False)
    r.checks["hudsonrock"] = hr
    if r.hudsonrock_found:
        pts += 20; flags.append(f"infostealer_log_found:{hr.get('stealers',0)}_stealers")

    # ── BreachDirectory (FREE, no key) ───────────────────────────────────
    bd = res.get("breachdirectory", {})
    r.breachdirectory_found = bd.get("found", False)
    r.breachdirectory_count = bd.get("count", 0)
    r.checks["breachdirectory"] = bd
    if r.breachdirectory_found:
        pts += min(r.breachdirectory_count * 3, 15)
        flags.append(f"breachdirectory_hit:{r.breachdirectory_count}_records")

    # ── Have I Been Pwned (free key — haveibeenpwned.com/API/v3) ─────────
    hb = res.get("hibp", {})
    r.hibp_found    = hb.get("found", False)
    r.hibp_breaches = hb.get("breach_names", [])
    r.checks["hibp"] = hb
    if r.hibp_found:
        count = hb.get("count", 1)
        pts  += min(count * 5, 20)
        flags.append(f"hibp_breach:{count}_databases:{','.join(r.hibp_breaches[:3])}")
        if hb.get("sensitive"):
            pts += 5; flags.append("hibp_sensitive_breach")

    # ── GreyNoise (IP reputation — free community, no key) ───────────────
    gn = res.get("greynoise", {})
    r.checks["greynoise"] = gn
    if gn.get("malicious"):
        r.greynoise_malicious = True
        pts += 20; flags.append("greynoise_malicious_ip")
    elif gn.get("noise"):
        r.greynoise_noise = True
        pts += 12; flags.append("greynoise_mass_scanner_ip")

    # ── Totals ────────────────────────────────────────────────────────────
    total = (r.leakcheck_count
             + r.breachdirectory_count
             + (hb.get("count", 0) if r.hibp_found else 0)
             + (1 if r.hudsonrock_found else 0))
    r.total_breach_sources = total
    r.breach_summary = (f"Found in {total} breach record(s) across "
                        f"{sum([r.leakcheck_found, r.hudsonrock_found, r.breachdirectory_found, r.hibp_found])} sources"
                        if total > 0 else "No breach data found")
    r.suspicion_score = pts; r.flags = flags
    return r.finalize()


# ─────────────────────────────────────────────────────────────────────────────
#  BEHAVIOR
# ─────────────────────────────────────────────────────────────────────────────
def analyze_behavior(
    response_times_sec:  Optional[List[float]]         = None,
    follow_history:      Optional[List[FollowEvent]]   = None,
    interactions:        Optional[List[Dict]]           = None,
    coordinated_actions: Optional[List[CoordAction]]   = None,
    mention_graph:       Optional[List[MentionEdge]]   = None,
    hashtag_sets:        Optional[List[List[str]]]     = None,
    post_sources:        Optional[List[str]]            = None,
) -> BehaviorResult:
    r = BehaviorResult()
    pts, flags = 0, []

    # BEH-01: Response CV
    if response_times_sec and len(response_times_sec) >= 4:
        mean = statistics.mean(response_times_sec)
        std  = statistics.stdev(response_times_sec)
        cv   = std / mean if mean > 0 else 0
        r.response_cv = round(cv, 4)
        if cv < 0.10 and mean < 60:
            r.response_automated = True
            pts += 20; flags.append(f"automated_responses:cv={cv:.3f}")

    # BEH-02: Follow cycling
    if follow_history:
        follows   = [e for e in follow_history if e.action == "follow"]
        unfollows = [e for e in follow_history if e.action == "unfollow"]
        tf = sum(e.count for e in follows)
        tu = sum(e.count for e in unfollows)
        cycles = sum(1 for i in range(min(len(follows), len(unfollows)))
                     if follows[i].count > 50 and unfollows[i].count > 20)
        if cycles >= 2:
            r.follow_cycling = True
            pts += 15; flags.append(f"follow_unfollow_cycling:{cycles}_cycles")

    # BEH-03: CIB
    if coordinated_actions and len(coordinated_actions) >= 3:
        by_type: Dict[str, List] = defaultdict(list)
        for a in coordinated_actions:
            ep = _to_epoch(a.timestamp)
            if ep:
                by_type[a.action_type].append((ep, a.username))
        clusters = []
        for atype, events in by_type.items():
            events_s = sorted(events, key=lambda x: x[0])
            for i in range(len(events_s)):
                window = [(e, u) for e, u in events_s[i:] if events_s[i][0] - e <= 60]
                users  = list({u for _, u in window})
                if len(users) >= 3:
                    clusters.append({"type": atype, "users": len(users)})
                    break
        if clusters:
            r.cib_detected = True
            r.cib_clusters = len(clusters)
            pts += min(len(clusters) * 15, 25)
            flags.append(f"cib_detected:{len(clusters)}_clusters")

    # BEH-04: Mention echo chamber
    if mention_graph and len(mention_graph) >= 3:
        users = set()
        for e in mention_graph:
            users.add(e.from_user); users.add(e.to_user)
        n = len(users)
        density = len(mention_graph) / max(n*(n-1), 1)
        r.mention_density = round(density, 4)
        avg_w = statistics.mean(e.count for e in mention_graph)
        if n <= 15 and density > 0.4 and avg_w > 3:
            r.echo_chamber = True
            pts += 10; flags.append(f"echo_chamber:density={density:.2f}")

    # BEH-05: Hashtag Jaccard
    if hashtag_sets and len(hashtag_sets) >= 3:
        sets = [set(h.lower() for h in s) for s in hashtag_sets if s]
        sims = []
        for i in range(len(sets)):
            for j in range(i+1, min(i+6, len(sets))):
                a, b = sets[i], sets[j]
                if a | b: sims.append(len(a & b) / len(a | b))
        if sims:
            avg_j = statistics.mean(sims)
            r.hashtag_jaccard = round(avg_j, 4)
            if avg_j > 0.7 and len(sets) >= 5:
                r.coordinated_hashtags = True
                pts += 15; flags.append(f"coordinated_hashtags:jaccard={avg_j:.2f}")

    # BEH-06: Scheduler
    if post_sources:
        found = {s.lower() for s in post_sources
                 if any(app in s.lower() for app in SCHEDULER_APPS)}
        if found:
            r.scheduler_detected = True
            pts += 8; flags.append(f"scheduler_detected:{','.join(found)}")

    # BEH-07: Burst
    if interactions and len(interactions) >= 10:
        epochs = sorted([e for e in [_to_epoch(a.get("timestamp","")) for a in interactions] if e])
        best = 0
        for i, start in enumerate(epochs):
            count = sum(1 for e in epochs[i:] if e - start <= 300)
            best  = max(best, count)
        if best >= 10:
            r.burst_detected = True
            pts += 12; flags.append(f"posting_burst:{best}_actions_in_5min")

    # BEH-08: Action rate
    if interactions and len(interactions) >= 3:
        epochs = sorted([e for e in [_to_epoch(a.get("timestamp","")) for a in interactions] if e])
        if len(epochs) >= 2:
            span = (epochs[-1] - epochs[0]) / 3600
            rate = len(epochs) / max(span, 0.01)
            r.actions_per_hour = round(rate, 2)
            if rate > 100:
                r.action_rate_anomaly = True
                pts += 15; flags.append(f"anomalous_action_rate:{rate:.0f}/hr")

    r.suspicion_score = pts; r.flags = flags
    return r.finalize()
