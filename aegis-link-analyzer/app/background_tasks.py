"""
Feature 11 — Async Background Processing
Aegis Link Analyzer | Phase 3

Enables non-blocking scan submission:
  POST /scan/async  → returns scan_id immediately (no waiting)
  GET  /scan/status/{scan_id} → poll for result when ready

Uses FastAPI BackgroundTasks + Redis for state storage.
Much simpler than Celery while achieving the same result for our use case.
Redis is already in our stack — no new infrastructure needed.

Why this matters:
  The current POST /scan blocks for 60-75 seconds waiting for VT + URLScan.
  In production (chatbot, browser extension), that's unacceptable.
  Background processing returns an ID in <1 second and lets the client poll.
"""

import json
import uuid
import asyncio
import redis.asyncio as redis
from datetime import datetime
from typing import Optional, Dict
from app.services import scan_url
from app.logger import log

REDIS_URL = "redis://redis:6379"

# Redis key prefix for background scan jobs
SCAN_JOB_PREFIX = "scan:job:"
SCAN_JOB_TTL = 60 * 60 * 2  # 2 hours — jobs expire after this


# ─────────────────────────────────────────────
# JOB STATUS CONSTANTS
# ─────────────────────────────────────────────

STATUS_PENDING   = "pending"
STATUS_RUNNING   = "running"
STATUS_COMPLETE  = "complete"
STATUS_FAILED    = "failed"


# ─────────────────────────────────────────────
# JOB CREATION
# ─────────────────────────────────────────────

async def create_scan_job(url: str) -> str:
    """
    Creates a new background scan job.
    Stores initial state in Redis and returns the job ID.

    Returns: job_id (UUID string)
    """
    job_id = str(uuid.uuid4())
    job_key = f"{SCAN_JOB_PREFIX}{job_id}"

    initial_state = {
        "job_id": job_id,
        "url": url,
        "status": STATUS_PENDING,
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
        "progress_message": "Job queued, scan will begin shortly..."
    }

    try:
        r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        await r.set(job_key, json.dumps(initial_state), ex=SCAN_JOB_TTL)
        log.info(f"📋 Background scan job created: {job_id} for {url}")
    except Exception as e:
        log.error(f"Failed to create scan job in Redis: {e}")
        raise

    return job_id


async def _update_job_status(job_id: str, updates: Dict):
    """Updates a job's Redis state with new fields."""
    try:
        r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        job_key = f"{SCAN_JOB_PREFIX}{job_id}"
        current = await r.get(job_key)
        if current:
            state = json.loads(current)
            state.update(updates)
            await r.set(job_key, json.dumps(state), ex=SCAN_JOB_TTL)
    except Exception as e:
        log.warning(f"Failed to update job {job_id} status: {e}")


# ─────────────────────────────────────────────
# BACKGROUND SCAN RUNNER
# ─────────────────────────────────────────────

async def run_background_scan(job_id: str, url: str):
    """
    The actual scan that runs in the background.
    Called by FastAPI's BackgroundTasks — non-blocking.

    Updates Redis state at each stage so clients can track progress.
    """
    log.info(f"🔄 Background scan started: {job_id}")

    try:
        # Mark as running
        await _update_job_status(job_id, {
            "status": STATUS_RUNNING,
            "started_at": datetime.utcnow().isoformat(),
            "progress_message": "Running local intelligence checks (Phase 1 + 2)..."
        })

        # Run the full scan (this is the same scan_url() from services.py)
        result = await scan_url(url)

        # Mark as complete with result
        await _update_job_status(job_id, {
            "status": STATUS_COMPLETE,
            "completed_at": datetime.utcnow().isoformat(),
            "result": result,
            "progress_message": f"Scan complete — {result.get('risk_level', 'Unknown')} detected"
        })

        log.success(f"✅ Background scan complete: {job_id} — {result.get('risk_level')}")

    except Exception as e:
        error_msg = str(e)
        log.error(f"❌ Background scan failed: {job_id} — {error_msg}")

        await _update_job_status(job_id, {
            "status": STATUS_FAILED,
            "completed_at": datetime.utcnow().isoformat(),
            "error": error_msg,
            "progress_message": f"Scan failed: {error_msg}"
        })


# ─────────────────────────────────────────────
# JOB STATUS RETRIEVAL
# ─────────────────────────────────────────────

async def get_scan_job_status(job_id: str) -> Optional[Dict]:
    """
    Retrieves the current status of a background scan job.

    Returns:
        dict with job state, or None if job not found / expired.
    """
    try:
        r = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        job_key = f"{SCAN_JOB_PREFIX}{job_id}"
        data = await r.get(job_key)

        if not data:
            return None

        state = json.loads(data)

        # Calculate elapsed time for running jobs
        if state.get("status") == STATUS_RUNNING and state.get("started_at"):
            try:
                started = datetime.fromisoformat(state["started_at"])
                elapsed = (datetime.utcnow() - started).seconds
                state["elapsed_seconds"] = elapsed
            except Exception:
                pass

        return state

    except Exception as e:
        log.error(f"Failed to get job {job_id} status: {e}")
        return None
