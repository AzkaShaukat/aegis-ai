#!/usr/bin/env python3
"""
Aegis AI — Unified Test Suite  |  v2.0.0
Tests: 100+  |  Port: 8000

Usage:
  python tests/test_aegis.py
  python tests/test_aegis.py --host http://localhost:8000
  python tests/test_aegis.py --skip-ollama   (skip LLM tests)
  python tests/test_aegis.py --skip-network  (skip external HEAD/API calls)
  python tests/test_aegis.py --verbose
  python tests/test_aegis.py --section block1
  python tests/test_aegis.py --section block4
"""
import sys, json, time, argparse
from typing import Any, Dict, Optional
import urllib.request, urllib.error

GREEN  = "\033[92m"; RED   = "\033[91m"; YELLOW = "\033[93m"
BLUE   = "\033[94m"; CYAN  = "\033[96m"; BOLD   = "\033[1m"
DIM    = "\033[2m";  RESET = "\033[0m"

# Minimal 1×1 JPEG for vision tests
TINY_JPEG = (
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8U"
    "HRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAARCAABAAEDASIA"
    "AhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/xAAU"
    "AQEAAAAAAAAAAAAAAAAAAAAA/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEQMRAD8A"
    "KwAB/9k="
)


def _get(obj, path):
    for key in path.split("."):
        if obj is None: return None
        obj = obj.get(key) if isinstance(obj, dict) else None
    return obj


def _assert(resp, assertions):
    failures = []
    for path_op, expected in assertions.items():
        if path_op.startswith("__"): continue
        path, op = (path_op.rsplit("__", 1) if "__" in path_op else (path_op, "eq"))
        actual = _get(resp, path)
        try:
            if   op == "eq":       ok = actual == expected
            elif op == "neq":      ok = actual != expected
            elif op == "gt":       ok = actual is not None and actual > expected
            elif op == "gte":      ok = actual is not None and actual >= expected
            elif op == "lt":       ok = actual is not None and actual < expected
            elif op == "lte":      ok = actual is not None and actual <= expected
            elif op == "in":       ok = expected in str(actual or "")
            elif op == "contains": ok = str(expected).lower() in str(actual or "").lower()
            elif op == "exists":   ok = actual is not None if expected else actual is None
            elif op == "true":     ok = actual is True
            elif op == "false":    ok = actual is False
            elif op == "len_gt":   ok = actual is not None and len(actual) > expected
            elif op == "len_gte":  ok = actual is not None and len(actual) >= expected
            elif op == "list_any": ok = isinstance(actual, list) and any(expected in str(x) for x in actual)
            elif op == "one_of":   ok = actual in expected
            elif op == "not_none": ok = actual is not None
            else:                  ok = False; failures.append(f"  Unknown op '{op}'")
            if not ok:
                failures.append(f"  {path} [{op}] expected={expected!r} got={actual!r}")
        except Exception as e:
            failures.append(f"  {path} [{op}] error: {e}")
    return failures


def _call(host, method, endpoint, payload=None, timeout=120, api_key=""):
    url  = f"{host}{endpoint}"
    body = json.dumps(payload).encode() if payload else None
    hdrs = {"Content-Type": "application/json", "User-Agent": "AegisTests/2.0"}
    if api_key:
        hdrs["X-API-Key"] = api_key
    req  = urllib.request.Request(url, data=body, headers=hdrs, method=method.upper())
    t0   = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read()), int((time.time()-t0)*1000)
    except urllib.error.HTTPError as e:
        try: b = json.loads(e.read())
        except: b = {"error": str(e)}
        return e.code, b, int((time.time()-t0)*1000)
    except Exception as ex:
        return 0, {"error": str(ex)}, 0


# Training samples (15 fake + 15 real)
FAKE_SAMPLES = [
    {"label": 1, "followers": 50000, "following": 150, "account_age_days": 3,
     "bio_scam_score": 45, "engagement_rate": 0.005, "block1_score": 65,
     "block2_score": 70, "block3_score": 55, "has_phone_in_bio": True},
    {"label": 1, "followers": 120000, "following": 200, "account_age_days": 7,
     "bio_scam_score": 60, "engagement_rate": 0.003, "block1_score": 70,
     "block2_score": 65, "block3_score": 60},
    {"label": 1, "followers": 30000, "following": 80, "account_age_days": 2,
     "bio_scam_score": 50, "block1_score": 75, "block2_score": 80, "block3_score": 50,
     "uses_scheduler": True},
    {"label": 1, "followers": 80000, "following": 110, "account_age_days": 5,
     "bio_scam_score": 55, "engagement_rate": 0.004, "block1_score": 60,
     "block2_score": 75, "block3_score": 65},
    {"label": 1, "followers": 200000, "following": 180, "account_age_days": 10,
     "bio_scam_score": 70, "block1_score": 80, "block2_score": 85, "block3_score": 70},
    {"label": 1, "followers": 45000, "following": 130, "account_age_days": 4,
     "bio_scam_score": 40, "block1_score": 55, "block2_score": 60, "block3_score": 40},
    {"label": 1, "followers": 15000, "following": 95, "account_age_days": 6,
     "bio_scam_score": 35, "block1_score": 50, "block2_score": 55, "block3_score": 45},
    {"label": 1, "followers": 90000, "following": 170, "account_age_days": 8,
     "bio_scam_score": 65, "block1_score": 72, "block2_score": 78, "block3_score": 68},
    {"label": 1, "followers": 60000, "following": 140, "account_age_days": 3,
     "bio_scam_score": 48, "block1_score": 62, "block2_score": 68, "block3_score": 58},
    {"label": 1, "followers": 25000, "following": 100, "account_age_days": 5,
     "bio_scam_score": 42, "block1_score": 58, "block2_score": 62, "block3_score": 52},
    {"label": 1, "followers": 110000, "following": 160, "account_age_days": 9,
     "bio_scam_score": 58, "block1_score": 68, "block2_score": 72, "block3_score": 62},
    {"label": 1, "followers": 35000, "following": 120, "account_age_days": 4,
     "bio_scam_score": 52, "block1_score": 64, "block2_score": 69, "block3_score": 57},
    {"label": 1, "followers": 75000, "following": 155, "account_age_days": 6,
     "bio_scam_score": 62, "block1_score": 73, "block2_score": 77, "block3_score": 67},
    {"label": 1, "followers": 18000, "following": 90, "account_age_days": 7,
     "bio_scam_score": 38, "block1_score": 52, "block2_score": 58, "block3_score": 48},
    {"label": 1, "followers": 55000, "following": 145, "account_age_days": 5,
     "bio_scam_score": 47, "block1_score": 61, "block2_score": 65, "block3_score": 55},
]
REAL_SAMPLES = [
    {"label": 0, "followers": 850, "following": 720, "account_age_days": 1200,
     "bio_scam_score": 2, "engagement_rate": 4.2, "block1_score": 5, "block2_score": 3, "block3_score": 4},
    {"label": 0, "followers": 4200, "following": 3800, "account_age_days": 900,
     "bio_scam_score": 0, "engagement_rate": 3.1, "block1_score": 3, "block2_score": 5, "block3_score": 2},
    {"label": 0, "followers": 1200, "following": 980, "account_age_days": 1500,
     "bio_scam_score": 1, "engagement_rate": 5.5, "block1_score": 8, "block2_score": 4, "block3_score": 5},
    {"label": 0, "followers": 280, "following": 310, "account_age_days": 800,
     "bio_scam_score": 0, "engagement_rate": 6.2, "block1_score": 2, "block2_score": 1, "block3_score": 3},
    {"label": 0, "followers": 6500, "following": 5800, "account_age_days": 600,
     "bio_scam_score": 3, "engagement_rate": 2.8, "block1_score": 10, "block2_score": 8, "block3_score": 6},
    {"label": 0, "followers": 920, "following": 850, "account_age_days": 1100,
     "bio_scam_score": 1, "engagement_rate": 4.8, "block1_score": 4, "block2_score": 2, "block3_score": 3},
    {"label": 0, "followers": 3400, "following": 2900, "account_age_days": 750,
     "bio_scam_score": 0, "engagement_rate": 3.6, "block1_score": 6, "block2_score": 7, "block3_score": 4},
    {"label": 0, "followers": 150, "following": 200, "account_age_days": 400,
     "bio_scam_score": 0, "engagement_rate": 8.1, "block1_score": 12, "block2_score": 5, "block3_score": 8},
    {"label": 0, "followers": 2100, "following": 1950, "account_age_days": 1300,
     "bio_scam_score": 2, "engagement_rate": 4.0, "block1_score": 7, "block2_score": 3, "block3_score": 5},
    {"label": 0, "followers": 7800, "following": 6200, "account_age_days": 500,
     "bio_scam_score": 5, "engagement_rate": 2.5, "block1_score": 15, "block2_score": 10, "block3_score": 9},
    {"label": 0, "followers": 450, "following": 480, "account_age_days": 950,
     "bio_scam_score": 0, "engagement_rate": 5.8, "block1_score": 3, "block2_score": 2, "block3_score": 4},
    {"label": 0, "followers": 1800, "following": 1650, "account_age_days": 700,
     "bio_scam_score": 1, "engagement_rate": 3.9, "block1_score": 8, "block2_score": 6, "block3_score": 5},
    {"label": 0, "followers": 5200, "following": 4800, "account_age_days": 1050,
     "bio_scam_score": 4, "engagement_rate": 2.9, "block1_score": 12, "block2_score": 9, "block3_score": 7},
    {"label": 0, "followers": 380, "following": 420, "account_age_days": 1400,
     "bio_scam_score": 0, "engagement_rate": 6.5, "block1_score": 4, "block2_score": 1, "block3_score": 2},
    {"label": 0, "followers": 2700, "following": 2400, "account_age_days": 850,
     "bio_scam_score": 2, "engagement_rate": 3.3, "block1_score": 9, "block2_score": 7, "block3_score": 6},
]


def run_tests(host, verbose, skip_ollama, skip_network, section_filter, api_key=""):
    passed = failed = skipped = 0
    t_start = time.time()

    def section(title, tag=None, color=CYAN):
        if section_filter and tag and section_filter.lower() not in tag.lower():
            return False
        print(f"\n{color}{'═'*70}\n  {BOLD}{title}{RESET}{color}\n{'═'*70}{RESET}")
        return True

    def run(tid, desc, method, endpoint, payload, assertions,
            skip_if=False, note="", tag=""):
        nonlocal passed, failed, skipped
        if section_filter and tag and section_filter.lower() not in tag.lower():
            return
        if skip_if:
            skipped += 1
            print(f"  [{YELLOW}{tid:>14}{RESET}] {YELLOW}SKIP{RESET}  {desc}")
            if note: print(f"               {DIM}{note}{RESET}")
            return
        status, resp, ms = _call(host, method, endpoint, payload, api_key=api_key)
        failures = []
        if status == 0:
            failures.append(f"  Connection failed: {resp.get('error','?')}")
        elif status >= 400:
            if not assertions.get("__expect_error"):
                failures.append(f"  HTTP {status}: {resp.get('detail', resp.get('error','?'))}")
        if not failures:
            failures = _assert(resp, assertions)
        tag_str = f"[{tid:>14}]"
        if not failures:
            passed += 1
            print(f"  {GREEN}{tag_str} PASS{RESET}  {desc}  {DIM}({ms}ms){RESET}")
            if verbose:
                print(f"               {DIM}{json.dumps(resp, default=str)[:280]}…{RESET}")
        else:
            failed += 1
            print(f"  {RED}{tag_str} FAIL{RESET}  {desc}  {DIM}({ms}ms){RESET}")
            for f in failures: print(f"  {RED}{f}{RESET}")

    # ── Banner ──────────────────────────────────────────────────────────
    print(f"\n{BOLD}{BLUE}{'█'*70}")
    print(f"  Aegis AI — Unified Fake Profile Detector  |  Test Suite v2.0.0")
    print(f"  Target: {host}  |  API Key: {'set ('+api_key+')' if api_key else 'none'}")
    print(f"{'█'*70}{RESET}")

    # ── Connectivity ────────────────────────────────────────────────────
    status, resp, ms = _call(host, "GET", "/health", api_key=api_key)
    if status != 200:
        print(f"  {RED}✗ Server not reachable at {host} (HTTP {status})")
        print(f"    docker-compose up --build{RESET}")
        sys.exit(1)
    print(f"  {GREEN}✓ Server healthy — v{resp.get('version','?')} ({ms}ms){RESET}")
    feats = resp.get("features", {})
    for k, v in feats.items():
        if isinstance(v, bool):
            print(f"    {'✓' if v else '○'} {k}")

    # ════════════════════════════════════════════════════════════════════
    if section("BLOCK 1 — Identity & Profile Foundation", "block1"):
        run("AG-B1-001", "Username: high entropy flagged",
            "POST", "/analyze/username",
            {"username": "xk7q2mf9p3"},
            {"suspicion_score__gt": 0, "entropy_score__gt": 3.0}, tag="block1")

        run("AG-B1-002", "Username: brand impersonation PayPal",
            "POST", "/analyze/username",
            {"username": "paypa1_support"},
            {"impersonates_brand__not_none": True, "suspicion_score__gt": 15}, tag="block1")

        run("AG-B1-003", "Username: leet impersonation",
            "POST", "/analyze/username",
            {"username": "0fficial_nadra"},
            {"leet_impersonation__true": True}, tag="block1")

        run("AG-B1-004", "Username: normal — low score",
            "POST", "/analyze/username",
            {"username": "ahmed_ali"},
            {"suspicion_score__lt": 20, "random_pattern__false": True}, tag="block1")

        run("AG-B1-005", "Username: excessive digits",
            "POST", "/analyze/username",
            {"username": "user123456789"},
            {"excessive_digits__true": True}, tag="block1")

        run("AG-B1-006", "Account: very new account flagged",
            "POST", "/analyze/account",
            {"account_age_days": 2, "followers": 50000, "bio": "Forex expert"},
            {"new_account_signal__true": True, "suspicion_score__gt": 0}, tag="block1")

        run("AG-B1-007", "Account: high F/F ratio flagged",
            "POST", "/analyze/account",
            {"followers": 100000, "following": 50, "account_age_days": 400, "bio": "Hello"},
            {"high_ff_ratio_signal__true": True}, tag="block1")

        run("AG-B1-008", "Account: empty bio flagged",
            "POST", "/analyze/account",
            {"followers": 5000, "bio": "", "account_age_days": 200},
            {"bio_empty__true": True}, tag="block1")

        run("AG-B1-009", "Account: excessive post rate",
            "POST", "/analyze/account",
            {"followers": 10000, "posts_count": 5000, "account_age_days": 10,
             "bio": "I post a lot"},
            {"suspicion_score__gt": 0}, tag="block1")

        run("AG-B1-010", "Email: disposable domain flagged",
            "POST", "/analyze/email",
            {"email": "test@mailinator.com"},
            {"is_disposable__true": True, "suspicion_score__gt": 0}, tag="block1")

        run("AG-B1-011", "Email: invalid format",
            "POST", "/analyze/email",
            {"email": "notanemail"},
            {"valid_format__false": True, "suspicion_score__gt": 0}, tag="block1")

        run("AG-B1-012", "Email: role account flagged",
            "POST", "/analyze/email",
            {"email": "admin@example.com"},
            {"is_role_account__true": True}, tag="block1")

        run("AG-B1-013", "Phone: missing phone → error",
            "POST", "/analyze/phone",
            {},
            {"__expect_error": True}, tag="block1")

    # ════════════════════════════════════════════════════════════════════
    if section("BLOCK 2 — Content & Language Intelligence", "block2"):
        run("AG-B2-001", "Bio: financial scam language",
            "POST", "/analyze/bio",
            {"bio": "Forex signals expert. Guaranteed profit daily. 100% risk free income."},
            {"suspicion_score__gt": 0,
             "scam_category_hits__not_none": True}, tag="block2")

        run("AG-B2-002", "Bio: PK-specific NADRA scam",
            "POST", "/analyze/bio",
            {"bio": "Official NADRA helpdesk. Verify your CNIC and get prize."},
            {"suspicion_score__gt": 0}, tag="block2")

        run("AG-B2-003", "Bio: crypto wallet address",
            "POST", "/analyze/bio",
            {"bio": "Donate to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"},
            {"has_crypto_wallet__true": True, "suspicion_score__gt": 0}, tag="block2")

        run("AG-B2-004", "Bio: phone number in bio",
            "POST", "/analyze/bio",
            {"bio": "Contact me: 03001234567 for investment tips"},
            {"has_phone_in_bio__true": True}, tag="block2")

        run("AG-B2-005", "Bio: clean bio — low score",
            "POST", "/analyze/bio",
            {"bio": "Software engineer at LUMS. Lahore Pakistan."},
            {"suspicion_score__lt": 20}, tag="block2")

        run("AG-B2-006", "Bio: excessive emojis",
            "POST", "/analyze/bio",
            {"bio": "🔥💰💎🚀✅🎯💯🏆 DM me for signals! 💪🤑"},
            {"suspicion_score__gt": 0, "emoji_density__gt": 0}, tag="block2")

        run("AG-B2-007", "Posts: bot posting CV",
            "POST", "/analyze/posts",
            {"posts": [
                {"text": "Buy now!", "timestamp": f"2026-03-01T10:00:{i:02d}Z"}
                for i in range(10)
            ]},
            {"bot_posting_pattern__true": True}, tag="block2")

        run("AG-B2-008", "Posts: copy-paste detection",
            "POST", "/analyze/posts",
            {"posts": [
                {"text": "Invest now get profit DM me guaranteed returns"},
                {"text": "Invest now earn profit message me guaranteed income"},
                {"text": "Invest today get profit contact me guaranteed gains"},
                {"text": "Invest now make profit write me guaranteed success"},
                {"text": "Invest now earn money inbox me guaranteed results"},
            ]},
            {"copy_paste_score__gt": 0.4}, tag="block2")

        run("AG-B2-009", "Posts: scam template pattern",
            "POST", "/analyze/posts",
            {"posts": [
                {"text": "Send 0.1 BTC and receive 0.5 BTC back. 100% guaranteed!"},
                {"text": "Limited slots open. DM me now for trading signals!"},
                {"text": "Make $500 per day working from home guaranteed!"},
            ]},
            {"template_hits__gt": 0, "suspicion_score__gt": 0}, tag="block2")

        run("AG-B2-010", "Posts: scheduler detection",
            "POST", "/analyze/posts",
            {"posts": [
                {"text": "Good morning!", "source_app": "Buffer"},
                {"text": "Midday update", "source_app": "Hootsuite"},
                {"text": "Evening post",  "source_app": "Buffer"},
            ]},
            {"scheduler_detected__true": True, "scheduler_apps__len_gt": 0}, tag="block2")

        run("AG-B2-011", "Links: shortener detected",
            "POST", "/analyze/links",
            {"extra_links": ["https://bit.ly/3xScamLink"]},
            {"links_analyzed__gte": 1, "link_details__len_gte": 1}, tag="block2",
            skip_if=skip_network)

        run("AG-B2-012", "Links: lookalike domain",
            "POST", "/analyze/links",
            {"extra_links": ["https://paypa1.com/login", "https://g00gle.com"]},
            {"lookalike_count__gt": 0}, tag="block2",
            skip_if=skip_network)

        run("AG-B2-013", "Language: script mismatch",
            "POST", "/analyze/language",
            {"bio": "مرحبا أنا مستثمر خبير أرسل لي المال",
             "claimed_location": "USA"},
            {"script_mismatch__true": True, "suspicion_score__gt": 0}, tag="block2")

        run("AG-B2-014", "Language: multilanguage farm",
            "POST", "/analyze/language",
            {"bio": "Hello مرحبا こんにちは Привет 你好 안녕하세요"},
            {"multilang_farm__true": True}, tag="block2")

    # ════════════════════════════════════════════════════════════════════
    if section("BLOCK 3 — Network & Social Intelligence", "block3"):
        run("AG-B3-001", "Engagement: very low rate → ghost followers",
            "POST", "/analyze/engagement",
            {"claimed_platform": "instagram", "followers": 200000,
             "post_samples_eng": [{"likes": 5, "comments": 0, "shares": 0}] * 5},
            {"ghost_follower_signal__true": True, "suspicion_score__gt": 0}, tag="block3")

        run("AG-B3-002", "Engagement: purchased followers",
            "POST", "/analyze/engagement",
            {"claimed_platform": "twitter", "followers": 20000,
             "follower_sample": [
                 {"default_avatar": True, "no_bio": True, "no_posts": True,
                  "created_recently": True, "zero_followers": True}
             ] * 40 + [{"default_avatar": False}] * 10},
            {"purchased_followers__true": True, "bot_follower_pct__gt": 30}, tag="block3")

        run("AG-B3-003", "Engagement: follower spike",
            "POST", "/analyze/engagement",
            {"claimed_platform": "instagram", "followers": 100000,
             "follower_history": (
                 [{"date": f"2026-03-{i:02d}", "followers": 1000 + i * 50} for i in range(1, 10)]
                 + [{"date": "2026-03-10", "followers": 80000}]
             )},
            {"spike_detected__true": True, "spike_gain__gt": 0}, tag="block3")

        run("AG-B3-004", "OSINT: no query → error flag",
            "POST", "/analyze/osint",
            {},
            {"__expect_error": True}, tag="block3")

        run("AG-B3-005", "OSINT: email query — fields returned",
            "POST", "/analyze/osint",
            {"email": "test@example.com"},
            {"queried_email__eq": "test@example.com",
             "risk_level__exists": True,
             "breach_summary__exists": True}, tag="block3",
            skip_if=skip_network)

        run("AG-B3-006", "Behavior: automated response CV",
            "POST", "/analyze/behavior",
            {"response_times_sec": [30.0, 30.1, 29.9, 30.0, 30.2, 30.0, 29.8, 30.1]},
            {"response_automated__true": True,
             "response_cv__lt": 0.02,
             "suspicion_score__gt": 0}, tag="block3")

        run("AG-B3-007", "Behavior: CIB cluster",
            "POST", "/analyze/behavior",
            {"coordinated_actions": [
                {"timestamp": f"2026-03-01T10:00:{i:02d}Z",
                 "username": f"user{i}", "action_type": "like_post_XYZ"}
                for i in range(20)
            ]},
            {"cib_detected__true": True, "cib_clusters__gt": 0}, tag="block3")

        run("AG-B3-008", "Behavior: coordinated hashtags",
            "POST", "/analyze/behavior",
            {"posts": [
                {"text": "text", "hashtags": ["imran_khan", "pti", "pakistan", "justice", "free"]}
            ] * 10},
            {"coordinated_hashtags__exists": True}, tag="block3")

        run("AG-B3-009", "Behavior: posting burst",
            "POST", "/analyze/behavior",
            {"interactions": [
                {"timestamp": f"2026-03-01T10:00:{i:02d}Z", "action_type": "post"}
                for i in range(15)
            ]},
            {"burst_detected__true": True}, tag="block3")

        run("AG-B3-010", "Behavior: anomalous action rate",
            "POST", "/analyze/behavior",
            {"interactions": [
                {"timestamp": f"2026-03-01T10:{i//60:02d}:{i%60:02d}Z",
                 "action_type": "like"} for i in range(300)
            ]},
            {"action_rate_anomaly__true": True, "actions_per_hour__gt": 100}, tag="block3")

        run("AG-B3-011", "CrossPlatform: structure returned",
            "POST", "/analyze/crossplatform",
            {"username": "testuser_aegis_xyz999"},
            {"username__eq": "testuser_aegis_xyz999",
             "platforms_checked__gt": 0,
             "risk_level__exists": True}, tag="block3",
            skip_if=skip_network)

    # ════════════════════════════════════════════════════════════════════
    if section("BLOCK 4 — AI/ML Holistic Scoring", "block4"):
        run("AG-B4-001", "Stylometry: scam bio — bot score elevated",
            "POST", "/analyze/stylometry",
            {"bio": "INVEST NOW!!! 100% PROFIT GUARANTEED!!! DM ME!!! ACT FAST!!!"},
            {"available__true": True, "stylometry_bot_score__gt": 0,
             "capitalization_rate__gt": 0}, tag="block4")

        run("AG-B4-002", "Stylometry: uniform posts → high uniformity",
            "POST", "/analyze/stylometry",
            {"posts": [
                {"text": "Invest now get profit DM for signals guaranteed"},
                {"text": "Invest now earn profit message for info guaranteed"},
                {"text": "Invest now make money contact for details guaranteed"},
                {"text": "Invest now earn cash write for tips guaranteed"},
                {"text": "Invest now get rich inbox for guide guaranteed"},
            ]},
            {"available__true": True,
             "text_uniformity_score__not_none": True}, tag="block4")

        run("AG-B4-003", "Stylometry: normal text — low score",
            "POST", "/analyze/stylometry",
            {"bio": "Software engineer at LUMS. Building distributed systems. Love cricket."},
            {"available__true": True,
             "vocabulary_richness__gt": 0.4,
             "stylometry_bot_score__lt": 30}, tag="block4")

        run("AG-B4-004", "Stylometry: no text → error",
            "POST", "/analyze/stylometry",
            {},
            {"available__false": True}, tag="block4")

        run("AG-B4-005", "sklearn: train on 30 samples",
            "POST", "/train/sklearn",
            {"samples": FAKE_SAMPLES + REAL_SAMPLES},
            {"success__true": True, "samples_used__eq": 30,
             "accuracy__gt": 0.0, "feature_count__gt": 0}, tag="block4")

        run("AG-B4-006", "sklearn: model info after training",
            "GET", "/model/info", None,
            {"loaded__true": True, "accuracy__exists": True}, tag="block4")

        run("AG-B4-007", "sklearn: too few samples → fail",
            "POST", "/train/sklearn",
            {"samples": FAKE_SAMPLES[:3]},
            {"__expect_error": True}, tag="block4")

        run("AG-B4-008", "sklearn: only fake samples → fail",
            "POST", "/train/sklearn",
            {"samples": FAKE_SAMPLES},
            {"success__false": True}, tag="block4")

        run("AG-B4-009", "Ollama holistic: scam bio",
            "POST", "/analyze/ollama",
            {"bio": "Double your BTC guaranteed. Send crypto get back 2x. DM now!",
             "username": "cryptoscam99", "followers": 50000, "account_age_days": 3},
            {"available__true": True, "scam_score__gt": 0,
             "fraud_type__exists": True, "reasoning__exists": True},
            skip_if=skip_ollama, tag="block4",
            note="Requires: ollama pull mistral")

        run("AG-B4-010", "Ollama holistic: legitimate profile",
            "POST", "/analyze/ollama",
            {"bio": "Engineer at LUMS. Love cricket and hiking.",
             "username": "normal_dev", "followers": 500, "account_age_days": 900},
            {"available__true": True, "scam_score__lt": 60},
            skip_if=skip_ollama, tag="block4")

        run("AG-B4-011", "Vision: no image → error",
            "POST", "/analyze/vision",
            {},
            {"__expect_error": True}, tag="block4")

        run("AG-B4-012", "Vision: base64 image accepted",
            "POST", "/analyze/vision",
            {"profile_pic_base64": TINY_JPEG, "profile_pic_mime": "image/jpeg"},
            {"available__exists": True, "model__exists": True},
            skip_if=skip_ollama, tag="block4",
            note="Requires: ollama pull llava:7b")

    # ════════════════════════════════════════════════════════════════════
    if section("★ UNIFIED PIPELINE — /analyze/profile", "unified"):
        run("AG-UNI-001", "Full pipeline: crypto scammer profile",
            "POST", "/analyze/profile",
            {"username": "cryptoking_forex",
             "bio": "Forex expert. Guaranteed 500% profit. DM for signals. 03001234567",
             "followers": 50000, "following": 100,
             "account_age_days": 5, "claimed_platform": "instagram",
             "posts": [
                 {"text": "Send 0.1 BTC get 0.5 BTC back guaranteed! DM NOW!"},
                 {"text": "Limited slots open. $500/day guaranteed income!"},
                 {"text": "Another withdrawal proof! DM for signals NOW!"},
             ],
             "run_ollama": False, "run_vision": False, "run_sklearn": True},
            {"verdict.final_score__gte": 0,
             "verdict.risk_level__exists": True,
             "verdict.fraud_type__exists": True,
             "verdict.summary__exists": True,
             "verdict.recommendation__exists": True,
             "verdict.analysis_ms__gt": 0,
             "verdict.top_flags__exists": True,
             "identity__exists": True,
             "content__exists": True}, tag="unified")

        run("AG-UNI-002", "Full pipeline: legitimate profile",
            "POST", "/analyze/profile",
            {"username": "ahmed_engineer",
             "bio": "Software engineer at LUMS. Love cricket.",
             "followers": 400, "following": 380,
             "account_age_days": 900, "claimed_platform": "twitter",
             "run_ollama": False, "run_vision": False, "run_sklearn": True},
            {"verdict.risk_level__one_of": ["clean", "low"],
             "verdict.final_score__lt": 40}, tag="unified")

        run("AG-UNI-003", "Full pipeline: PK government impersonation",
            "POST", "/analyze/profile",
            {"username": "nadra_official_pk",
             "bio": "Official NADRA helpdesk. Verify CNIC. Call 0800-NADRA for prize claim.",
             "followers": 15000, "following": 50,
             "claimed_location": "Pakistan", "account_age_days": 10,
             "run_ollama": False, "run_vision": False, "run_sklearn": False},
            {"verdict.final_score__gt": 0,
             "content__exists": True}, tag="unified")

        run("AG-UNI-004", "Full pipeline: block scores correctly echoed",
            "POST", "/analyze/profile",
            {"username": "testuser",
             "bio": "Hello world",
             "run_ollama": False, "run_vision": False, "run_sklearn": False},
            {"verdict.block1_score__not_none": True,
             "verdict.blocks_run__len_gt": 0}, tag="unified")

        run("AG-UNI-005", "Full pipeline: fraud_type always present",
            "POST", "/analyze/profile",
            {"username": "some_user",
             "run_ollama": False, "run_vision": False, "run_sklearn": False},
            {"verdict.fraud_type__exists": True,
             "verdict.confidence__one_of": ["high", "medium", "low"]}, tag="unified")

        run("AG-UNI-006", "Full pipeline: with email + phone OSINT",
            "POST", "/analyze/profile",
            {"username": "testuser_osint",
             "email": "test@example.com",
             "run_ollama": False, "run_vision": False, "run_sklearn": False,
             "run_osint": True},
            {"verdict.final_score__gte": 0,
             "network__exists": True}, tag="unified",
            skip_if=skip_network)

        run("AG-UNI-007", "Full pipeline: with Ollama",
            "POST", "/analyze/profile",
            {"username": "ollama_test_user",
             "bio": "I guarantee 1000% profit. Send me money now. DM for signals.",
             "followers": 75000, "following": 80, "account_age_days": 4,
             "run_ollama": True, "run_vision": False, "run_sklearn": True},
            {"verdict.final_score__gte": 0,
             "ai_ml__exists": True},
            skip_if=skip_ollama, tag="unified")

        run("AG-UNI-008", "Full pipeline: behavioral signals",
            "POST", "/analyze/profile",
            {"username": "bot_account",
             "bio": "Buy now",
             "response_times_sec": [30.0, 30.1, 29.9, 30.0, 30.2, 30.0, 30.1, 29.9],
             "interactions": [
                 {"timestamp": f"2026-03-01T10:00:{i:02d}Z", "action_type": "post"}
                 for i in range(15)
             ],
             "run_ollama": False, "run_vision": False, "run_sklearn": False},
            {"network__exists": True,
             "verdict.final_score__gte": 0}, tag="unified")

        run("AG-UNI-009", "Full pipeline: all_flags list present",
            "POST", "/analyze/profile",
            {"bio": "GUARANTEED PROFIT! DM NOW! FOREX SIGNALS!",
             "followers": 50000, "following": 100, "account_age_days": 3,
             "run_ollama": False, "run_vision": False},
            {"verdict.all_flags__exists": True}, tag="unified")

        run("AG-UNI-010", "Score guide endpoint",
            "GET", "/analyze/score-guide", None,
            {"risk_thresholds__exists": True,
             "aggregation_weights__exists": True,
             "fraud_types__exists": True}, tag="unified")

        run("AG-UNI-011", "Root endpoint",
            "GET", "/", None,
            {"name__contains": "Aegis",
             "main_endpoint__contains": "/analyze/profile"}, tag="unified")

        run("AG-UNI-012", "Full pipeline: language geo check",
            "POST", "/analyze/profile",
            {"bio": "مرحبا أنا خبير في الفوركس أرسل لي المال الآن",
             "claimed_location": "USA",
             "run_ollama": False, "run_vision": False, "run_sklearn": False},
            {"content__exists": True,
             "verdict.final_score__gte": 0}, tag="unified")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t_start
    total   = passed + failed + skipped
    pct     = passed / max(total - skipped, 1) * 100

    print(f"\n{BOLD}{'─'*70}{RESET}")
    print(f"  {BOLD}Total: {total}  "
          f"{GREEN}Passed: {passed}{RESET}  "
          f"{RED}Failed: {failed}{RESET}  "
          f"{YELLOW}Skipped: {skipped}{RESET}  "
          f"({elapsed:.1f}s)")
    bar = int(40 * passed / max(total - skipped, 1))
    col = GREEN if pct >= 90 else (YELLOW if pct >= 70 else RED)
    print(f"  {GREEN}{'█'*bar}{DIM}{'░'*(40-bar)}{RESET}  {col}{BOLD}{pct:.1f}%{RESET}")

    if failed:
        print(f"\n  {RED}{BOLD}{failed} test(s) failed.{RESET}")
        sys.exit(1)
    print(f"\n  {GREEN}{BOLD}All tests passed! ✓{RESET}")
    print(f"{'═'*70}\n")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Aegis AI Test Suite")
    p.add_argument("--host",         default="http://localhost:8000")
    p.add_argument("--verbose",      action="store_true")
    p.add_argument("--skip-ollama",  action="store_true")
    p.add_argument("--skip-network", action="store_true")
    p.add_argument("--api-key",      default="1122", help="X-API-Key (default: 1122)")
    p.add_argument("--section",      default="",
                   help="Filter: block1|block2|block3|block4|unified")
    a = p.parse_args()
    run_tests(a.host, a.verbose, a.skip_ollama, a.skip_network, a.section,
              getattr(a, "api_key", "1122"))