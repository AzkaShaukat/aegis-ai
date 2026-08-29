"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  AEGIS AI — Social Media Fake Profile Detector                             ║
║  Unified API · All 4 Blocks · Single Entry Point                           ║
║  Port: 8000  |  Version: 2.0.0                                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

Blocks:
  1 — Identity & Profile Foundation   (username, photo, account, phone, email)
  2 — Content & Language Intelligence (bio NLP, posts, links, language/geo)
  3 — Network & Social Intelligence   (engagement, cross-platform, OSINT, behavior)
  4 — AI/ML Holistic Scoring         (Ollama LLM, LLaVA vision, sklearn, stylometry)

Key Endpoint:
  POST /analyze/profile  →  Full pipeline — all blocks parallel → final verdict
"""
import time, logging, asyncio
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config       import get_settings
from app.redis_client import redis_health, cache_get, cache_set
from app.models import (
    # Request
    ProfileRequest, TrainRequest,
    # Block 1
    UsernameResult, AccountResult, PhoneResult, EmailResult,
    # Block 2
    BioResult, PostsResult, LinksResult, LanguageResult,
    # Block 3
    EngagementResult, CrossPlatformResult, OsintResult, BehaviorResult,
    # Block 4
    OllamaHolisticResult, LlavaResult, SklearnResult, StylometryResult,
    # Final
    FullProfileResult, FinalVerdict, TrainResult, HealthResponse,
    RiskLevel, FraudType, score_to_risk,
)
from app.analyzers.block1.identity import (
    analyze_username, analyze_account, analyze_phone, analyze_email,
)
from app.analyzers.block2.content import (
    analyze_bio, analyze_posts, analyze_links, analyze_language,
)
from app.analyzers.block3.network import (
    analyze_engagement, analyze_cross_platform, analyze_osint, analyze_behavior,
)
from app.analyzers.block4.ai_ml import (
    ollama_holistic, ollama_vision, ollama_health, ollama_health as _oh,
    analyze_stylometry, sklearn_predict, load_sklearn_model, train_sklearn,
    aggregate,
)
from data.patterns import URL_RE

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger   = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("═" * 60)
    logger.info("  AEGIS AI — Unified Fake Profile Detector  v2.0.0")
    logger.info("═" * 60)
    # Load sklearn model if it exists
    loaded = load_sklearn_model()
    logger.info(f"  sklearn model: {'✓ loaded' if loaded else '○ not trained yet'}")
    # Check Ollama
    oh = await ollama_health()
    logger.info(f"  Ollama status: {oh.get('status','?')}")
    if oh.get("text_model_ready"):
        logger.info(f"  Text model ({settings.ollama_model}): ✓")
    if oh.get("vision_model_ready"):
        logger.info(f"  Vision model ({settings.ollama_vision_model}): ✓")
    logger.info("═" * 60)
    yield
    logger.info("[Aegis] Shutting down.")


app = FastAPI(
    title="Aegis AI — Fake Profile Detector",
    description=(
        "**Unified social media fake profile detection API.**\n\n"
        "All 4 detection blocks in a single API:\n"
        "- Block 1: Identity & Profile Foundation\n"
        "- Block 2: Content & Language Intelligence\n"
        "- Block 3: Network & Social Intelligence\n"
        "- Block 4: AI/ML Holistic Scoring (Ollama + sklearn + LLaVA)\n\n"
        "**Main endpoint:** `POST /analyze/profile` — runs everything in parallel."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


# ── Auth + timing middleware ──────────────────────────────────────────────────
@app.middleware("http")
async def middleware(request: Request, call_next):
    start = time.time()
    if settings.aegis_api_key:
        skip = {"/health", "/docs", "/redoc", "/openapi.json"}
        if request.url.path not in skip:
            key = request.headers.get("X-API-Key", "")
            if key != settings.aegis_api_key:
                return JSONResponse({"error": "Invalid or missing X-API-Key"}, status_code=401)
    resp = await call_next(request)
    ms   = int((time.time() - start) * 1000)
    resp.headers["X-Response-Time-Ms"] = str(ms)
    resp.headers["X-Aegis-Version"]    = "2.0.0"
    return resp


# ═══════════════════════════════════════════════════════════════════════════
#  HEALTH
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    rh = await redis_health()
    oh = await ollama_health()
    from app.analyzers.block4.ai_ml import _model
    return HealthResponse(
        status="healthy", version="2.0.0", redis=rh,
        features={
            # Block 1
            "username_analysis":       True,
            "account_meta_analysis":   True,
            "phone_analysis_ipqs":     bool(settings.ipqs_api_key),
            "email_analysis":          True,
            # Block 2
            "bio_nlp_13_checks":       True,
            "post_analysis_9_checks":  True,
            "link_safety_virustotal":  bool(settings.virustotal_api_key),
            "link_safety_urlscan":     bool(settings.urlscan_api_key),
            "language_geo_analysis":   True,
            # Block 3
            "engagement_quality":      True,
            "cross_platform_sherlock": True,
            "dark_web_ahmia":          True,
            "osint_leakcheck":         True,
            "osint_hudsonrock_free":   settings.hudsonrock_enabled,
            "osint_shodan":            bool(settings.shodan_api_key),
            "osint_greynoise_free":    True,
            "behavioral_cib":          True,
            # Block 4
            "ollama_holistic_llm":     oh.get("text_model_ready", False),
            "ollama_vision_llava":     oh.get("vision_model_ready", False),
            "sklearn_model_loaded":    _model is not None,
            "sklearn_training":        True,
            "stylometry_analysis":     True,
            "score_aggregation":       True,
            "redis":                   rh == "healthy",
            # Meta
            "ollama_text_model":       oh.get("available_models", []),
        }
    )


@app.get("/health/ollama", tags=["System"])
async def health_ollama():
    return await ollama_health()


@app.get("/model/info", tags=["ML Training"])
async def model_info():
    import app.analyzers.block4.ai_ml as _ai
    if _ai._model is None:
        return {"loaded": False, "message": "No model trained. POST /train/sklearn first."}
    return {"loaded": True, **_ai._model_meta}


# ═══════════════════════════════════════════════════════════════════════════
#  ★ MAIN UNIFIED ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════
@app.post(
    "/analyze/profile",
    response_model=FullProfileResult,
    tags=["★ Unified Analysis"],
    summary="Full pipeline — all 4 blocks in parallel → final verdict",
)
async def analyze_profile(req: ProfileRequest):
    """
    **The primary Aegis AI endpoint.**

    Accepts a full profile and runs all 4 detection blocks in parallel:
    - Block 1: Username entropy, account meta, phone/email validation
    - Block 2: Bio NLP (13 checks), post analysis (9 checks), link safety, language/geo
    - Block 3: Engagement quality, Sherlock cross-platform, OSINT breach, behavioral CIB
    - Block 4: Ollama holistic LLM, LLaVA vision, sklearn RandomForest, stylometry

    Returns per-block details + weighted final verdict.
    """
    t0     = time.time()
    blocks_run: List[str] = []
    all_flags: List[str]  = []

    # ── BLOCK 1: Identity ────────────────────────────────────────────────
    b1_results: Dict[str, Any] = {}
    b1_score = 0

    if req.username:
        u_res = analyze_username(req.username)
        b1_results["username"] = u_res.model_dump()
        b1_score += u_res.suspicion_score
        all_flags.extend(u_res.flags)

    acc_res = analyze_account(
        followers=req.followers, following=req.following,
        posts_count=req.posts_count, account_age_days=req.account_age_days,
        bio=req.bio, has_profile_pic=bool(req.profile_pic_url),
        is_verified=req.is_verified,
    )
    b1_results["account"] = acc_res.model_dump()
    b1_score += acc_res.suspicion_score
    all_flags.extend(acc_res.flags)

    phone_res: Optional[PhoneResult] = None
    email_res: Optional[EmailResult] = None

    async def _run_phone():
        nonlocal phone_res
        if req.phone:
            phone_res = await analyze_phone(req.phone)
            b1_results["phone"] = phone_res.model_dump()
            all_flags.extend(phone_res.flags)

    async def _run_email():
        nonlocal email_res
        if req.email:
            email_res = await analyze_email(req.email)
            b1_results["email"] = email_res.model_dump()
            all_flags.extend(email_res.flags)

    await asyncio.gather(_run_phone(), _run_email())

    if phone_res: b1_score += phone_res.suspicion_score
    if email_res: b1_score += email_res.suspicion_score
    b1_score = min(b1_score, 100)
    blocks_run.append("block1")

    # ── BLOCK 2: Content ─────────────────────────────────────────────────
    b2_results: Dict[str, Any] = {}
    b2_score = 0

    if req.bio:
        bio_res = analyze_bio(req.bio, req.claimed_location)
        b2_results["bio"] = bio_res.model_dump()
        b2_score += bio_res.suspicion_score
        all_flags.extend(bio_res.flags)

    if req.posts:
        posts_res = analyze_posts(req.posts)
        b2_results["posts"] = posts_res.model_dump()
        b2_score += posts_res.suspicion_score
        all_flags.extend(posts_res.flags)

    # Collect all URLs from bio + posts + extra_links
    urls: List[str] = list(req.extra_links or [])
    if req.bio:
        urls.extend(URL_RE.findall(req.bio))
    if req.posts:
        for p in req.posts:
            if p.text:
                urls.extend(URL_RE.findall(p.text))
    urls = list(dict.fromkeys(urls))[:20]

    link_res: Optional[LinksResult] = None
    if urls:
        link_res = await analyze_links(urls)
        b2_results["links"] = link_res.model_dump()
        b2_score += link_res.suspicion_score
        all_flags.extend(link_res.flags)

    lang_res = analyze_language(
        bio=req.bio, posts=req.posts,
        claimed_location=req.claimed_location,
        claimed_timezone=req.claimed_timezone,
        exif_gps_lat=req.exif_gps_lat,
        exif_gps_lon=req.exif_gps_lon,
    )
    b2_results["language"] = lang_res.model_dump()
    b2_score += lang_res.suspicion_score
    all_flags.extend(lang_res.flags)

    b2_score = min(b2_score, 100)
    blocks_run.append("block2")

    # ── BLOCK 3: Network ─────────────────────────────────────────────────
    b3_results: Dict[str, Any] = {}
    b3_score = 0
    b3_coros: Dict[str, Any] = {}

    if req.followers is not None and req.claimed_platform:
        b3_coros["engagement"] = asyncio.to_thread(
            analyze_engagement,
            req.claimed_platform, req.followers, req.following,
            [p.model_dump() for p in (req.post_samples_eng or [])],
            req.follower_sample, req.follower_history,
        )

    if req.username and req.run_crossplatform:
        b3_coros["crossplatform"] = analyze_cross_platform(
            req.username, req.bio, full_scan=False,
        )

    if req.run_osint and any([req.email, req.phone, req.username, req.ip, req.domain]):
        b3_coros["osint"] = analyze_osint(
            email=req.email, phone=req.phone,
            username=req.username, ip=req.ip, domain=req.domain,
        )

    has_behavior = any([req.response_times_sec, req.follow_history,
                        req.interactions, req.coordinated_actions, req.mention_graph])
    if has_behavior:
        b3_coros["behavior"] = asyncio.to_thread(
            analyze_behavior,
            req.response_times_sec,
            req.follow_history, req.interactions,
            req.coordinated_actions, req.mention_graph,
            [list(p.hashtags) for p in (req.posts or []) if p.hashtags],
            [p.source_app for p in (req.posts or []) if p.source_app],
        )

    if b3_coros:
        keys  = list(b3_coros)
        outs  = await asyncio.gather(*b3_coros.values(), return_exceptions=True)
        for k, v in zip(keys, outs):
            if isinstance(v, Exception):
                logger.warning(f"[Block3:{k}] {v}")
                continue
            b3_results[k] = v.model_dump()
            b3_score += v.suspicion_score
            all_flags.extend(v.flags)
        b3_score = min(b3_score, 100)
    blocks_run.append("block3")

    # ── BLOCK 4: AI/ML ───────────────────────────────────────────────────
    b4_results: Dict[str, Any] = {}
    ollama_res: Optional[OllamaHolisticResult] = None
    vision_res: Optional[LlavaResult]          = None
    stylo_res:  Optional[StylometryResult]     = None
    sklearn_res: Optional[SklearnResult]       = None

    # Stylometry (sync, fast)
    if req.bio or req.posts:
        post_texts = [p.text for p in (req.posts or []) if p.text]
        stylo_res  = analyze_stylometry(req.bio, post_texts or None)
        b4_results["stylometry"] = stylo_res.model_dump()

    # Async AI tasks
    b4_coros: Dict[str, Any] = {}

    if req.run_ollama and settings.ollama_enabled:
        post_texts_b4 = [p.text for p in (req.posts or []) if p.text][:5]
        b4_coros["ollama"] = ollama_holistic(
            username=req.username, bio=req.bio,
            claimed_platform=req.claimed_platform,
            claimed_location=req.claimed_location,
            followers=req.followers, following=req.following,
            account_age_days=req.account_age_days,
            sample_posts=post_texts_b4 or None,
            is_verified=req.is_verified,
            all_flags=all_flags[:20],
        )

    if req.run_vision and settings.ollama_vision_enabled and req.profile_pic_base64:
        b4_coros["vision"] = ollama_vision(
            req.profile_pic_base64, req.profile_pic_mime, req.username,
        )

    if b4_coros:
        keys  = list(b4_coros)
        outs  = await asyncio.gather(*b4_coros.values(), return_exceptions=True)
        for k, v in zip(keys, outs):
            if isinstance(v, Exception):
                logger.warning(f"[Block4:{k}] {v}")
                continue
            b4_results[k] = v.model_dump()
            if k == "ollama": ollama_res = v
            if k == "vision": vision_res = v

    # sklearn
    if req.run_sklearn and settings.sklearn_enabled:
        bio_len    = len(req.bio) if req.bio else None
        phone_bio  = any("phone_in_bio" in f for f in all_flags)
        scheduler  = any("scheduler" in f for f in all_flags)
        cp_score   = None
        if b2_results.get("posts"):
            cp_score = b2_results["posts"].get("copy_paste_score")
        eng_rate   = (b3_results.get("engagement", {}) or {}).get("engagement_rate")
        platforms  = (b3_results.get("crossplatform", {}) or {}).get("sherlock_count")
        breaches   = (b3_results.get("osint", {}) or {}).get("total_breach_sources")

        sklearn_res = await asyncio.to_thread(
            sklearn_predict,
            followers=req.followers, following=req.following,
            account_age_days=req.account_age_days, posts_count=req.posts_count,
            bio_length=bio_len, bio_scam_score=b2_score // 3,
            is_verified=req.is_verified, has_phone_in_bio=phone_bio,
            uses_scheduler=scheduler, engagement_rate=eng_rate,
            copy_paste_score=cp_score, platforms_found=platforms,
            breach_count=breaches,
            ttr=stylo_res.vocabulary_richness if stylo_res and stylo_res.available else None,
            avg_word_len=stylo_res.avg_word_length if stylo_res and stylo_res.available else None,
            text_uniformity=stylo_res.text_uniformity_score if stylo_res and stylo_res.available else None,
            excl_density=stylo_res.flesch_reading_ease if stylo_res and stylo_res.available else None,
            block1_score=b1_score, block2_score=b2_score, block3_score=b3_score,
        )
        b4_results["sklearn"] = sklearn_res.model_dump()

    blocks_run.append("block4")

    # ── FINAL AGGREGATION ────────────────────────────────────────────────
    verdict = aggregate(
        username=req.username, claimed_platform=req.claimed_platform,
        block1_score=b1_score, block2_score=b2_score, block3_score=b3_score,
        ollama_result=ollama_res, vision_result=vision_res,
        sklearn_result=sklearn_res, stylo_result=stylo_res,
        all_flags=all_flags, analysis_start=t0, blocks_run=blocks_run,
    )

    return FullProfileResult(
        username=req.username,
        claimed_platform=req.claimed_platform,
        identity=b1_results if b1_results else None,
        content=b2_results if b2_results else None,
        network=b3_results if b3_results else None,
        ai_ml=b4_results if b4_results else None,
        verdict=verdict,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  BLOCK 1 — Individual sub-endpoints
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/analyze/username", response_model=UsernameResult, tags=["Block 1 — Identity"])
async def ep_username(req: ProfileRequest):
    if not req.username:
        raise HTTPException(400, "username is required")
    return analyze_username(req.username)


@app.post("/analyze/account", response_model=AccountResult, tags=["Block 1 — Identity"])
async def ep_account(req: ProfileRequest):
    return analyze_account(
        req.followers, req.following, req.posts_count,
        req.account_age_days, req.bio,
        has_profile_pic=bool(req.profile_pic_url),
        is_verified=req.is_verified,
    )


@app.post("/analyze/phone", response_model=PhoneResult, tags=["Block 1 — Identity"])
async def ep_phone(req: ProfileRequest):
    if not req.phone:
        raise HTTPException(400, "phone is required")
    return await analyze_phone(req.phone)


@app.post("/analyze/email", response_model=EmailResult, tags=["Block 1 — Identity"])
async def ep_email(req: ProfileRequest):
    if not req.email:
        raise HTTPException(400, "email is required")
    return await analyze_email(req.email)


# ═══════════════════════════════════════════════════════════════════════════
#  BLOCK 2 — Individual sub-endpoints
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/analyze/bio", response_model=BioResult, tags=["Block 2 — Content"])
async def ep_bio(req: ProfileRequest):
    if not req.bio:
        raise HTTPException(400, "bio is required")
    return analyze_bio(req.bio, req.claimed_location)


@app.post("/analyze/posts", response_model=PostsResult, tags=["Block 2 — Content"])
async def ep_posts(req: ProfileRequest):
    if not req.posts:
        raise HTTPException(400, "posts are required")
    return analyze_posts(req.posts)


@app.post("/analyze/links", response_model=LinksResult, tags=["Block 2 — Content"])
async def ep_links(req: ProfileRequest):
    urls = list(req.extra_links or [])
    if req.bio: urls.extend(URL_RE.findall(req.bio))
    if req.posts:
        for p in req.posts:
            if p.text: urls.extend(URL_RE.findall(p.text))
    urls = list(dict.fromkeys(urls))[:20]
    if not urls:
        raise HTTPException(400, "No URLs found — provide extra_links or bio/posts with URLs")
    return await analyze_links(urls)


@app.post("/analyze/language", response_model=LanguageResult, tags=["Block 2 — Content"])
async def ep_language(req: ProfileRequest):
    return analyze_language(
        req.bio, req.posts, req.claimed_location,
        req.claimed_timezone, req.exif_gps_lat, req.exif_gps_lon,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  BLOCK 3 — Individual sub-endpoints
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/analyze/engagement", response_model=EngagementResult, tags=["Block 3 — Network"])
async def ep_engagement(req: ProfileRequest):
    if req.followers is None or not req.claimed_platform:
        raise HTTPException(400, "followers and claimed_platform are required")
    try:
        return await asyncio.to_thread(
            analyze_engagement,
            req.claimed_platform, req.followers, req.following,
            req.post_samples_eng or [],
            req.follower_sample, req.follower_history,
        )
    except Exception as e:
        logger.error(f"[engagement] {e}", exc_info=True)
        raise HTTPException(500, f"Engagement analysis error: {str(e)}")


@app.post("/analyze/crossplatform", response_model=CrossPlatformResult, tags=["Block 3 — Network"])
async def ep_crossplatform(req: ProfileRequest):
    if not req.username:
        raise HTTPException(400, "username is required")
    return await analyze_cross_platform(req.username, req.bio)


@app.post("/analyze/crossplatform/full", response_model=CrossPlatformResult,
          tags=["Block 3 — Network"])
async def ep_crossplatform_full(req: ProfileRequest):
    if not req.username:
        raise HTTPException(400, "username is required")
    return await analyze_cross_platform(req.username, req.bio, full_scan=True)


@app.post("/analyze/osint", response_model=OsintResult, tags=["Block 3 — Network"])
async def ep_osint(req: ProfileRequest):
    if not any([req.email, req.phone, req.username, req.ip, req.domain]):
        raise HTTPException(400, "Provide at least one of: email, phone, username, ip, domain")
    return await analyze_osint(
        email=req.email, phone=req.phone, username=req.username,
        ip=req.ip, domain=req.domain,
    )


@app.post("/analyze/behavior", response_model=BehaviorResult, tags=["Block 3 — Network"])
async def ep_behavior(req: ProfileRequest):
    return await asyncio.to_thread(
        analyze_behavior,
        req.response_times_sec, req.follow_history, req.interactions,
        req.coordinated_actions, req.mention_graph,
        [list(p.hashtags) for p in (req.posts or []) if p.hashtags],
        [p.source_app for p in (req.posts or []) if p.source_app],
    )


# ═══════════════════════════════════════════════════════════════════════════
#  BLOCK 4 — Individual sub-endpoints
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/analyze/stylometry", response_model=StylometryResult, tags=["Block 4 — AI/ML"])
async def ep_stylometry(req: Optional[ProfileRequest] = None):
    if req is None:
        return StylometryResult(available=False, error="No text provided")
    post_texts = [p.text for p in (req.posts or []) if p.text]
    return analyze_stylometry(req.bio, post_texts or None)


@app.post("/analyze/ollama", response_model=OllamaHolisticResult, tags=["Block 4 — AI/ML"])
async def ep_ollama(req: ProfileRequest):
    post_texts = [p.text for p in (req.posts or []) if p.text][:5]
    return await ollama_holistic(
        req.username, req.bio, req.claimed_platform, req.claimed_location,
        req.followers, req.following, req.account_age_days,
        post_texts or None, req.is_verified, [],
    )


@app.post("/analyze/vision", response_model=LlavaResult, tags=["Block 4 — AI/ML"])
async def ep_vision(req: ProfileRequest):
    if not req.profile_pic_base64:
        raise HTTPException(400, "profile_pic_base64 is required")
    return await ollama_vision(req.profile_pic_base64, req.profile_pic_mime, req.username)


# ═══════════════════════════════════════════════════════════════════════════
#  ML TRAINING
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/train/sklearn", response_model=TrainResult, tags=["ML Training"])
async def ep_train(req: TrainRequest):
    """
    Train the RandomForestClassifier on labelled profile data.
    Min 10 samples. Mix of label=1 (fake) and label=0 (real) required.
    Model saved to disk and used immediately.
    """
    result = await asyncio.to_thread(train_sklearn, req.samples)
    from app.models import TrainResult as TR
    return TR(**result)


# ═══════════════════════════════════════════════════════════════════════════
#  QUICK UTILITY ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/analyze/score-guide", tags=["System"])
async def score_guide():
    """Returns the scoring thresholds and fraud type definitions."""
    return {
        "risk_thresholds": {
            "0-9":   "CLEAN — no significant signals",
            "10-29": "LOW — minor suspicious indicators, monitor",
            "30-49": "MEDIUM — moderate risk, review recommended",
            "50-69": "HIGH — strong fake signals, action likely needed",
            "70-100": "CRITICAL — confirmed fake/scam, block immediately",
        },
        "aggregation_weights": {
            "ollama_holistic_llm": 1.3,
            "block3_osint_behavior": 1.2,
            "llava_vision": 1.2,
            "sklearn_randomforest": 1.1,
            "block2_content_nlp": 1.0,
            "block1_identity": 0.9,
            "stylometry": 0.7,
        },
        "fraud_types": [ft.value for ft in FraudType],
        "free_apis": [
            "HudsonRock Cavalier (stealer logs)",
            "GreyNoise Community (IP reputation)",
            "Ahmia.fi (Tor mentions)",
            "LeakCheck.io (10/day breach lookup)",
            "Ollama (local LLM — offline)",
        ],
    }


@app.get("/", tags=["System"])
async def root():
    return {
        "name":    "Aegis AI — Fake Profile Detector",
        "version": "2.0.0",
        "docs":    "/docs",
        "health":  "/health",
        "main_endpoint": "POST /analyze/profile",
        "all_endpoints": [
            "POST /analyze/profile (full pipeline)",
            "POST /analyze/username",
            "POST /analyze/account",
            "POST /analyze/phone",
            "POST /analyze/email",
            "POST /analyze/bio",
            "POST /analyze/posts",
            "POST /analyze/links",
            "POST /analyze/language",
            "POST /analyze/engagement",
            "POST /analyze/crossplatform",
            "POST /analyze/osint",
            "POST /analyze/behavior",
            "POST /analyze/stylometry",
            "POST /analyze/ollama",
            "POST /analyze/vision",
            "POST /train/sklearn",
            "GET  /model/info",
            "GET  /health",
            "GET  /health/ollama",
        ],
    }
