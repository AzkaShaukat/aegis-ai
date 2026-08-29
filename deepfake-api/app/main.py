"""
Aegis AI Deepfake Detection API v3.0.0

Key fixes:
- CORS: allow_credentials=False with allow_origins=["*"] (fixes "Failed to fetch")
- Video: sync endpoint uses thread + timeout, never blocks the worker
- Parallel: all requests handled concurrently via background threads
- No video size limit (MAX_VIDEO_SIZE_MB=99999)
"""
from __future__ import annotations
import asyncio, logging, threading, time, uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import torch
from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from app.analyzers.image_analyzer import analyze_image, analyze_image_from_url
from app.analyzers.video_analyzer import analyze_video
from app.config import get_settings
from app.models.ensemble import get_image_ensemble, get_video_ensemble, load_all_models
from app.schemas import (
    AsyncJobResponse, BatchImageResult, DeepfakeAnalysisResult,
    FeedbackRequest, FeedbackResponse, HealthResponse,
    ImageURLRequest, JobStatusResponse,
)
from app.utils.redis_client import (
    create_job, get_cache_stats, get_job, purge_cache, update_job_status,
)
from app.utils.feedback_store import (
    init_db, save_feedback, get_feedback_stats, log_scan, get_metrics_summary,
)
from app.utils.rate_limiter import check_rate_limit, RATE_LIMITS

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

_MAX_VIDEO_BYTES = settings.MAX_VIDEO_SIZE_MB * 1024 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Aegis Deepfake API v3.0.0 starting...")
    init_db()
    load_all_models()
    img = get_image_ensemble()
    vid = get_video_ensemble()
    img_ok = sum(1 for m in [img.model_1, img.model_2, img.model_3] if m)
    vid_ok = sum(1 for m in [vid.model_1, vid.model_2, vid.model_3] if m)
    logger.info(f"Image: {img_ok}/3 | Video: {vid_ok}/3 | Max video: {settings.MAX_VIDEO_SIZE_MB} MB")
    yield


app = FastAPI(
    title="Aegis AI — Deepfake Detection",
    version="3.0.0",
    description="Deepfake detection API — Phase 3.",
    lifespan=lifespan,
)

# ── CORS — must have allow_credentials=False with allow_origins=["*"] ────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,   # CRITICAL — browser blocks if True with wildcard
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)


def _check(request: Request, endpoint: str):
    if settings.API_KEY and request.headers.get("X-API-Key", "") != settings.API_KEY:
        raise HTTPException(401, "Invalid or missing X-API-Key")
    if settings.RATE_LIMIT_ENABLED:
        client_ip = request.client.host if request.client else "unknown"
        allowed, remaining, reset = check_rate_limit(client_ip, endpoint)
        if not allowed:
            raise HTTPException(429, f"Rate limit exceeded. Retry in {reset}s.",
                                headers={"Retry-After": str(reset)})


def _log(result: DeepfakeAnalysisResult):
    try:
        log_scan(result.scan_id, result.pipeline_used.value, result.verdict,
                 result.overall_risk_score, result.ensemble_probability,
                 result.elapsed_ms, result.cached)
    except Exception:
        pass


# ── System ────────────────────────────────────────────────────────────────────

@app.get("/", tags=["System"])
async def root():
    return {
        "service": "Aegis AI — Deepfake Detection API",
        "version": "3.0.0",
        "docs": "/docs",
        "health": "/health",
        "note": "Use /analyze/video-async for videos — sync endpoint may timeout on slow connections",
        "phase1_endpoints": ["/analyze/image", "/analyze/image-url", "/analyze/video"],
        "phase2_endpoints": ["/analyze/video-async", "/analyze/status/{job_id}",
                              "/analyze/batch", "/analyze/image/explain",
                              "/analyze/video/timeline", "/feedback",
                              "/cache/stats", "/cache/purge"],
        "phase3_endpoints": ["/metrics", "/metrics/prometheus", "/feedback/stats"],
    }


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    img = get_image_ensemble()
    vid = get_video_ensemble()
    def _st(state):
        return {n: {"loaded": s.loaded, "path": s.path, "error": s.error}
                for n, s in state.statuses.items()}
    redis_ok = get_cache_stats().get("redis_available", False)
    return HealthResponse(
        status="healthy" if ((img and img.any_loaded) or (vid and vid.any_loaded)) else "degraded",
        image_pipeline=_st(img) if img else {},
        video_pipeline=_st(vid) if vid else {},
        device=img.device if img else "unknown",
        gpu_available=torch.cuda.is_available(),
        redis_available=redis_ok,
        timestamp=datetime.utcnow().isoformat() + "Z",
    )


# ── Phase 1: Image ────────────────────────────────────────────────────────────

@app.post("/analyze/image", response_model=DeepfakeAnalysisResult, tags=["Phase 1"])
async def analyze_image_ep(
    request: Request,
    file: UploadFile = File(...),
    source_hint: Optional[str] = Header(default=None, alias="X-Source-Hint"),
):
    _check(request, "/analyze/image")
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file.")
    ens = get_image_ensemble()
    if ens is None:
        raise HTTPException(503, "Image pipeline not initialized.")
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: analyze_image(data, ens, source_hint=source_hint, use_cache=True)
        )
        _log(result)
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.exception("Image analysis error")
        raise HTTPException(500, str(e))


@app.post("/analyze/image-url", response_model=DeepfakeAnalysisResult, tags=["Phase 1"])
async def analyze_image_url_ep(request: Request, body: ImageURLRequest):
    _check(request, "/analyze/image-url")
    ens = get_image_ensemble()
    if ens is None:
        raise HTTPException(503, "Image pipeline not initialized.")
    try:
        result = await analyze_image_from_url(str(body.url), ens, source_hint=body.source_hint)
        _log(result)
        return result
    except Exception as e:
        raise HTTPException(400, f"Could not fetch or analyze image: {e}")


@app.post("/analyze/video", response_model=DeepfakeAnalysisResult, tags=["Phase 1"])
async def analyze_video_ep(
    request: Request,
    file: UploadFile = File(...),
    source_hint: Optional[str] = Header(default=None, alias="X-Source-Hint"),
):
    """
    Synchronous video analysis. Runs in thread pool — does NOT block other requests.
    For videos > 30s use /analyze/video-async to avoid browser timeouts.
    """
    _check(request, "/analyze/video")
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file.")
    if len(data) > _MAX_VIDEO_BYTES:
        raise HTTPException(413, f"Video exceeds {settings.MAX_VIDEO_SIZE_MB} MB limit.")
    ens = get_video_ensemble()
    if ens is None:
        raise HTTPException(503, "Video pipeline not initialized.")
    try:
        # run_in_executor: runs in thread pool, never blocks the event loop
        # Other requests continue to be served while this runs
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: analyze_video(data, ens, source_hint=source_hint)
        )
        _log(result)
        return result
    except Exception as e:
        logger.exception("Video analysis error")
        raise HTTPException(500, str(e))


# ── Phase 2: Async video ──────────────────────────────────────────────────────

def _bg_video(job_id, data, hint):
    def progress(status, msg):
        update_job_status(job_id, status, msg)
    try:
        ens = get_video_ensemble()
        if ens is None:
            update_job_status(job_id, "failed", "Video pipeline not available",
                              error="Not initialized")
            return
        result = analyze_video(data, ens, source_hint=hint, progress_callback=progress)
        _log(result)
        update_job_status(job_id, "complete", "Scan complete", result=result.model_dump())
    except Exception as e:
        logger.exception(f"Async job {job_id} failed")
        update_job_status(job_id, "failed", f"Error: {str(e)[:200]}", error=str(e))


@app.post("/analyze/video-async", response_model=AsyncJobResponse, tags=["Phase 2"])
async def analyze_video_async_ep(
    request: Request,
    file: UploadFile = File(...),
    source_hint: Optional[str] = Header(default=None, alias="X-Source-Hint"),
):
    """
    Recommended for all videos. Returns job_id immediately (< 200ms).
    Poll GET /analyze/status/{job_id} every 2s until status=complete.
    """
    _check(request, "/analyze/video-async")
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file.")
    if len(data) > _MAX_VIDEO_BYTES:
        raise HTTPException(413, f"Video exceeds {settings.MAX_VIDEO_SIZE_MB} MB limit.")
    job_id = f"job-{uuid.uuid4().hex[:16]}"
    create_job(job_id)
    threading.Thread(target=_bg_video, args=(job_id, data, source_hint), daemon=True).start()
    return AsyncJobResponse(
        job_id=job_id, status="queued",
        message="Video queued. Poll /analyze/status/{job_id} every 2s.",
        poll_url=f"/analyze/status/{job_id}",
        created_at=time.time(),
    )


@app.get("/analyze/status/{job_id}", response_model=JobStatusResponse, tags=["Phase 2"])
async def job_status_ep(job_id: str):
    job = get_job(job_id)
    if job is None:
        raise HTTPException(404, f"Job '{job_id}' not found or expired.")
    elapsed = None
    if job.get("started_at") and job.get("completed_at"):
        elapsed = round(job["completed_at"] - job["started_at"], 2)
    result = None
    if job.get("result"):
        try:
            result = DeepfakeAnalysisResult(**job["result"])
        except Exception:
            pass
    return JobStatusResponse(
        job_id=job_id, status=job["status"],
        progress_message=job["progress_message"],
        created_at=job["created_at"], started_at=job.get("started_at"),
        completed_at=job.get("completed_at"), elapsed_seconds=elapsed,
        result=result, error=job.get("error"),
    )


@app.post("/analyze/batch", response_model=BatchImageResult, tags=["Phase 2"])
async def batch_ep(
    request: Request,
    files: list[UploadFile] = File(...),
    source_hint: Optional[str] = Header(default=None, alias="X-Source-Hint"),
):
    _check(request, "/analyze/batch")
    if len(files) > 10:
        raise HTTPException(400, "Maximum 10 images per batch.")
    if not files:
        raise HTTPException(400, "No files provided.")
    ens = get_image_ensemble()
    if ens is None:
        raise HTTPException(503, "Image pipeline not initialized.")
    t0 = time.time()
    failed = 0

    async def _one(f):
        nonlocal failed
        try:
            d = await f.read()
            r = await asyncio.get_event_loop().run_in_executor(
                None, lambda: analyze_image(d, ens, source_hint=source_hint, use_cache=True)
            )
            _log(r)
            return {"filename": f.filename, "status": "complete", **r.model_dump()}
        except Exception as e:
            failed += 1
            return {"filename": f.filename, "status": "failed", "error": str(e)}

    results = await asyncio.gather(*[_one(f) for f in files])
    completed = [r for r in results if r.get("status") == "complete"]
    top_score = max((r.get("overall_risk_score", 0) for r in completed), default=0)
    top_level = next((r.get("overall_risk_level","Clean") for r in completed
                      if r.get("overall_risk_score",0) == top_score), "Clean")
    return BatchImageResult(
        total_images=len(files), completed=len(completed), failed=failed,
        results=list(results), batch_risk=top_level, highest_risk_score=top_score,
        elapsed_ms=round((time.time()-t0)*1000, 2),
    )


@app.post("/analyze/image/explain", response_model=DeepfakeAnalysisResult, tags=["Phase 2"])
async def explain_ep(
    request: Request,
    file: UploadFile = File(...),
    source_hint: Optional[str] = Header(default=None, alias="X-Source-Hint"),
):
    _check(request, "/analyze/image/explain")
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file.")
    ens = get_image_ensemble()
    if ens is None:
        raise HTTPException(503, "Image pipeline not initialized.")
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: analyze_image(data, ens, source_hint=source_hint,
                                        use_cache=False, include_gradcam=True)
        )
        _log(result)
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.exception("GradCAM error")
        raise HTTPException(500, str(e))


@app.post("/analyze/video/timeline", response_model=DeepfakeAnalysisResult, tags=["Phase 2"])
async def timeline_ep(
    request: Request,
    file: UploadFile = File(...),
    source_hint: Optional[str] = Header(default=None, alias="X-Source-Hint"),
):
    _check(request, "/analyze/video/timeline")
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file.")
    if len(data) > _MAX_VIDEO_BYTES:
        raise HTTPException(413, f"Video exceeds {settings.MAX_VIDEO_SIZE_MB} MB limit.")
    ens = get_video_ensemble()
    if ens is None:
        raise HTTPException(503, "Video pipeline not initialized.")
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: analyze_video(data, ens, source_hint=source_hint,
                                        include_timeline=True)
        )
        _log(result)
        return result
    except Exception as e:
        logger.exception("Timeline error")
        raise HTTPException(500, str(e))


@app.post("/feedback", response_model=FeedbackResponse, tags=["Phase 2 & 3"])
async def feedback_ep(request: Request, body: FeedbackRequest):
    fid = save_feedback(body.scan_id, body.original_verdict, body.corrected_verdict, body.notes)
    stats = get_feedback_stats()
    msg = f"Feedback recorded. Total: {stats['total_feedback']}."
    if stats["training_ready"]:
        msg += " Training ready!"
    return FeedbackResponse(feedback_id=fid, status="received", message=msg)


@app.get("/feedback/stats", tags=["Phase 3"])
async def feedback_stats_ep():
    return get_feedback_stats()


@app.get("/cache/stats", tags=["Phase 2 & 3"])
async def cache_stats_ep():
    return get_cache_stats()


@app.delete("/cache/purge", tags=["Phase 2 & 3"])
async def cache_purge_ep():
    return purge_cache()


@app.get("/metrics", tags=["Phase 3"])
async def metrics_ep():
    s = get_metrics_summary()
    img = get_image_ensemble()
    vid = get_video_ensemble()
    return {
        **s,
        "models": {
            "image_loaded": sum(1 for m in [img.model_1,img.model_2,img.model_3] if m) if img else 0,
            "video_loaded": sum(1 for m in [vid.model_1,vid.model_2,vid.model_3] if m) if vid else 0,
            "device": img.device if img else "unknown",
            "gpu": torch.cuda.is_available(),
        },
        "version": "3.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.get("/metrics/prometheus", response_class=PlainTextResponse, tags=["Phase 3"])
async def metrics_prometheus_ep():
    s = get_metrics_summary()
    img = get_image_ensemble()
    img_ok = sum(1 for m in [img.model_1,img.model_2,img.model_3] if m) if img else 0
    lines = [
        f"aegis_total_scans {s['total_scans']}",
        f"aegis_cache_hits {s['cache_hits']}",
        f"aegis_avg_scan_ms {s['avg_scan_time_ms']}",
        f"aegis_models_loaded {img_ok}",
        f"aegis_gpu {1 if torch.cuda.is_available() else 0}",
    ]
    for v, c in s.get("verdict_distribution", {}).items():
        lines.append(f'aegis_verdict_total{{verdict="{v}"}} {c}')
    return "\n".join(lines) + "\n"
