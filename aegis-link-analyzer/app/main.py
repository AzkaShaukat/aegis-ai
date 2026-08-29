"""
Aegis AI — Link Analysis Service
main.py | FastAPI Application
"""

import asyncio
import time
from fastapi import FastAPI, HTTPException, Depends, Query, BackgroundTasks, Request, Response
from fastapi.responses import StreamingResponse
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from contextlib import asynccontextmanager
from datetime import datetime
import redis.asyncio as redis
import httpx

from app.schemas import (
    LinkRequest, ScanResult,
    BulkScanRequest, BulkScanResponse, BulkScanResult,
    AsyncScanResponse, ScanJobStatus,
    FeedbackRequest, FeedbackResponse, FeedbackStats,
    MLPredictionResult, ScanMetrics,
)
from app.services import scan_url
from app.background_tasks import create_scan_job, run_background_scan, get_scan_job_status
from app.feedback import init_feedback_db, save_feedback, get_feedback_stats
from app.ml_classifier import load_model, is_model_loaded
from app.metrics import get_metrics, get_prometheus_metrics
from app.logger import log


# ─────────────────────────────────────────────────────────────────────────────
# APPLICATION LIFECYCLE
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting Aegis Link Analyzer...")

    try:
        redis_conn = redis.from_url("redis://redis:6379", encoding="utf-8", decode_responses=True)
        await FastAPILimiter.init(redis_conn)
        log.success("Redis connected.")
    except Exception as e:
        log.error(f"Redis unavailable: {e}")

    try:
        await init_feedback_db()
        log.success("Feedback database ready.")
    except Exception as e:
        log.error(f"Feedback DB error: {e}")

    ok, msg = load_model()
    if ok:
        log.success(f"ML classifier loaded: {msg}")
    else:
        log.warning(f"ML classifier unavailable: {msg}")

    yield
    await FastAPILimiter.close()


# ─────────────────────────────────────────────────────────────────────────────
# APPLICATION
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Aegis AI — Link Analysis Service",
    description=(
        "Multi-layer URL threat intelligence platform.\n\n"
        "Combines local heuristics, WHOIS/DNS/SSL analysis, "
        "real-time threat feed lookups, and a local ML classifier "
        "to detect phishing and malicious URLs with high accuracy.\n\n"
        "**Analysis layers:**\n"
        "- URL structural heuristics (14 checks)\n"
        "- WHOIS domain age & registrar analysis\n"
        "- DNS health & infrastructure checks\n"
        "- SSL/TLS certificate analysis\n"
        "- HTTP redirect chain tracing\n"
        "- URLhaus malware feed\n"
        "- OpenPhish phishing feed\n"
        "- Google Safe Browsing\n"
        "- VirusTotal (94 antivirus engines)\n"
        "- URLScan.io visual scanning\n"
        "- Local ML classifier (Random Forest)"
    ),
    version="4.0.0",
    lifespan=lifespan,
    contact={"name": "Aegis AI", "url": "https://github.com"},
    license_info={"name": "MIT"},
)


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Service"], summary="Service information")
def root():
    return {
        "service": "Aegis Link Analyzer",
        "version": "4.0.0",
        "status": "running",
        "docs": "/docs",
        "metrics": "/metrics",
    }


@app.get("/health", tags=["Service"], summary="Health check")
def health():
    return {
        "status": "healthy",
        "ml_model": "loaded" if is_model_loaded() else "unavailable",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# SCAN — Synchronous
# ─────────────────────────────────────────────────────────────────────────────

@app.post(
    "/scan",
    response_model=ScanResult,
    dependencies=[Depends(RateLimiter(times=5, seconds=60))],
    tags=["Scanning"],
    summary="Full URL scan",
    description=(
        "Performs a complete multi-layer threat analysis on the submitted URL.\n\n"
        "Runs all detection layers concurrently and returns a comprehensive report "
        "including risk level, confidence score, flag breakdown, and ML prediction.\n\n"
        "**Note:** This endpoint blocks until all external API polling completes (~60 seconds). "
        "For non-blocking use, see `POST /scan/async`.\n\n"
        "**Rate limit:** 5 requests per minute."
    ),
)
async def analyze_link(request: LinkRequest):
    log.info(f"Scan request: {request.url}")
    try:
        result = await scan_url(str(request.url))
        return result
    except Exception as e:
        log.error(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# SCAN — Bulk
# ─────────────────────────────────────────────────────────────────────────────

@app.post(
    "/scan/bulk",
    response_model=BulkScanResponse,
    dependencies=[Depends(RateLimiter(times=2, seconds=60))],
    tags=["Scanning"],
    summary="Bulk URL scan (up to 10 URLs)",
    description=(
        "Scans multiple URLs simultaneously. All scans run concurrently — "
        "total time equals the slowest individual scan, not their sum.\n\n"
        "Returns a summary response with per-URL results and identifies "
        "the highest-risk URL in the batch.\n\n"
        "**Limit:** 10 URLs per request. **Rate limit:** 2 requests per minute."
    ),
)
async def bulk_scan(request: BulkScanRequest):
    urls = [str(u) for u in request.urls]
    if len(urls) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 URLs per bulk scan request.")
    if len(urls) == 0:
        raise HTTPException(status_code=400, detail="At least 1 URL is required.")

    log.info(f"Bulk scan: {len(urls)} URLs")
    start = time.time()

    async def _scan_one(url: str) -> BulkScanResult:
        try:
            result = await scan_url(url)
            return BulkScanResult(
                url=url,
                status="complete",
                risk_level=result.get("risk_level"),
                confidence_score=result.get("confidence_score"),
                message=result.get("message"),
                total_flags=result.get("total_flags"),
                score_breakdown=result.get("score_breakdown"),
            )
        except Exception as e:
            return BulkScanResult(url=url, status="error", error=str(e))

    results = await asyncio.gather(*[_scan_one(u) for u in urls])

    risk_order = {"High Risk": 4, "Medium Risk": 3, "Low Risk": 2, "Safe": 1}
    completed = [r for r in results if r.status == "complete"]
    failed    = [r for r in results if r.status == "error"]

    top = max(completed, key=lambda r: risk_order.get(r.risk_level or "Safe", 0)) if completed else None
    duration = round(time.time() - start, 2)

    log.success(f"Bulk scan complete: {len(completed)}/{len(urls)} in {duration}s")

    return BulkScanResponse(
        total_urls=len(urls),
        completed=len(completed),
        failed=len(failed),
        results=list(results),
        scan_duration_seconds=duration,
        highest_risk_url=top.url if top else None,
        highest_risk_level=top.risk_level if top else None,
    )


# ─────────────────────────────────────────────────────────────────────────────
# SCAN — Async (Background)
# ─────────────────────────────────────────────────────────────────────────────

@app.post(
    "/scan/async",
    response_model=AsyncScanResponse,
    dependencies=[Depends(RateLimiter(times=10, seconds=60))],
    tags=["Scanning"],
    summary="Non-blocking URL scan",
    description=(
        "Submits a URL scan as a background job and returns a `job_id` immediately "
        "(typically under 100ms). The scan runs in the background.\n\n"
        "Poll `GET /scan/status/{job_id}` to check progress and retrieve results "
        "when `status` becomes `complete`.\n\n"
        "**Job states:** `pending` → `running` → `complete` or `failed`\n\n"
        "**Job TTL:** Jobs expire from Redis after 2 hours.\n\n"
        "**Rate limit:** 10 requests per minute."
    ),
)
async def async_scan(request: LinkRequest, background_tasks: BackgroundTasks):
    url = str(request.url)
    try:
        job_id = await create_scan_job(url)
        background_tasks.add_task(run_background_scan, job_id, url)
        return AsyncScanResponse(
            job_id=job_id,
            url=url,
            status="pending",
            message="Scan queued. Poll /scan/status/{job_id} for results.",
            poll_url=f"/scan/status/{job_id}",
            created_at=datetime.utcnow().isoformat(),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to queue scan: {e}")


@app.get(
    "/scan/status/{job_id}",
    response_model=ScanJobStatus,
    tags=["Scanning"],
    summary="Poll async scan result",
    description=(
        "Returns the current status of a background scan job.\n\n"
        "When `status` is `complete`, the full scan result is available in the `result` field.\n\n"
        "When `status` is `failed`, the `error` field contains the reason.\n\n"
        "Returns 404 if the job_id does not exist or has expired (2-hour TTL)."
    ),
)
async def get_scan_status(job_id: str):
    job = await get_scan_job_status(job_id)
    if job is None:
        raise HTTPException(
            status_code=404,
            detail=f"Scan job '{job_id}' not found or expired."
        )
    return ScanJobStatus(**{k: v for k, v in job.items() if k in ScanJobStatus.model_fields})


# ─────────────────────────────────────────────────────────────────────────────
# FEEDBACK
# ─────────────────────────────────────────────────────────────────────────────

@app.post(
    "/feedback",
    response_model=FeedbackResponse,
    tags=["Feedback"],
    summary="Submit a scan result correction",
    description=(
        "Report an incorrect scan result to improve detection accuracy.\n\n"
        "**feedback_type values:**\n"
        "- `false_positive` — System flagged as dangerous, URL is actually safe\n"
        "- `false_negative` — System said safe, URL is actually malicious\n"
        "- `wrong_level` — Risk level was incorrect (e.g., should be High not Medium)\n"
        "- `correct` — Result was accurate (positive confirmation)\n\n"
        "All submissions are stored and used to retrain the ML classifier."
    ),
)
async def submit_feedback(request: FeedbackRequest):
    try:
        result = await save_feedback(
            scan_id=request.scan_id,
            url=request.url,
            original_risk=request.original_risk,
            corrected_risk=request.corrected_risk,
            feedback_type=request.feedback_type,
            user_note=request.user_note,
            confidence_score=request.confidence_score,
            total_flags=request.total_flags,
            false_flags=request.false_flags or [],
        )
        return FeedbackResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/feedback/stats",
    response_model=FeedbackStats,
    tags=["Feedback"],
    summary="View feedback statistics",
    description=(
        "Returns summary statistics from all collected feedback.\n\n"
        "When `training_ready` is `true` (50+ samples collected), "
        "the ML classifier can be retrained using the collected corrections."
    ),
)
async def feedback_stats():
    try:
        return FeedbackStats(**(await get_feedback_stats()))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─────────────────────────────────────────────────────────────────────────────
# METRICS
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    "/metrics",
    tags=["Observability"],
    summary="Service metrics (JSON)",
    description=(
        "Returns runtime metrics including scan counts, risk distribution, "
        "cache performance, threat feed hit rates, and ML prediction statistics."
    ),
)
async def metrics_json():
    return await get_metrics()


@app.get(
    "/metrics/prometheus",
    tags=["Observability"],
    summary="Service metrics (Prometheus format)",
    description=(
        "Returns metrics in Prometheus text exposition format. "
        "Compatible with Prometheus scraping and Grafana dashboards."
    ),
    response_class=Response,
)
async def metrics_prometheus():
    content = await get_prometheus_metrics()
    return Response(content=content, media_type="text/plain; version=0.0.4")


# ─────────────────────────────────────────────────────────────────────────────
# SCREENSHOT PROXY
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    "/proxy-image",
    tags=["Utilities"],
    summary="Proxy external screenshot image",
    description=(
        "Fetches an external image (e.g., URLScan screenshot) server-side "
        "and serves it to the client. Necessary in environments with "
        "strict CORS policies or cross-origin restrictions."
    ),
)
async def proxy_image(url: str = Query(..., description="External image URL to proxy")):
    try:
        async with httpx.AsyncClient(
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AegisLinkAnalyzer/4.0)"}
        ) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                raise HTTPException(status_code=404, detail="Image not found at source URL")
            # FIX: Read all bytes into memory before client context closes
            image_bytes = resp.content
            content_type = resp.headers.get("content-type", "image/png")
            return Response(content=image_bytes, media_type=content_type)
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Image proxy error for {url}: {e}")
        raise HTTPException(status_code=404, detail="Could not fetch image")
