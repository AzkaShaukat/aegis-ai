"""
app/services_logic/deepfake_service.py
Deepfake Detection Service — Port 8004

Matches WhatsApp's deepfake service logic, adapted for web backend.
"""

from __future__ import annotations
import logging
from typing import Optional
import httpx

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

DEEPFAKE_URL = settings.deepfake_service_url


# ── API Calls ─────────────────────────────────────────────────────────────────
async def analyze_image_bytes(image_bytes: bytes, filename: str = "image.jpg") -> dict:
    """POST /analyze/image — multipart file upload."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0)) as client:
            r = await client.post(
                f"{DEEPFAKE_URL}/analyze/image",
                files={"file": (filename, image_bytes, "image/jpeg")},
            )
            if r.status_code == 200:
                return r.json()
            logger.warning("Deepfake image API returned %s", r.status_code)
    except httpx.ConnectError:
        logger.warning("Deepfake service not running on port 8004")
    except Exception as e:
        logger.error("Deepfake image analysis error: %s", e)
    return {"module_unavailable": True}


async def analyze_image_url(url: str) -> dict:
    """POST /analyze/image-url — analyze image from URL."""
    try:
        logger.info(f"Calling deepfake service at {DEEPFAKE_URL}/analyze/image-url with URL: {url}")
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0)) as client:
            r = await client.post(
                f"{DEEPFAKE_URL}/analyze/image-url",
                json={"url": url},
            )
            logger.info(f"Deepfake service responded with status {r.status_code}")
            if r.status_code == 200:
                return r.json()
            else:
                logger.warning(f"Deepfake service returned {r.status_code}: {r.text}")
    except httpx.ConnectError as e:
        logger.error(f"Deepfake service connection error: {e}")
    except httpx.TimeoutException:
        logger.error("Deepfake service timeout")
    except Exception as e:
        logger.error(f"Deepfake URL analysis error: {e}", exc_info=True)
    return {"module_unavailable": True}


async def analyze_video_bytes(video_bytes: bytes, filename: str = "video.mp4") -> dict:
    """POST /analyze/video — synchronous video analysis."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(120.0)) as client:
            r = await client.post(
                f"{DEEPFAKE_URL}/analyze/video",
                files={"file": (filename, video_bytes, "video/mp4")},
            )
            if r.status_code == 200:
                return r.json()
    except httpx.ConnectError:
        logger.warning("Deepfake service not running on port 8004")
    except Exception as e:
        logger.error("Deepfake video analysis error: %s", e)
    return {"module_unavailable": True}


async def submit_video_async(video_bytes: bytes, filename: str = "video.mp4") -> dict:
    """POST /analyze/video-async — submit and get job_id."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            r = await client.post(
                f"{DEEPFAKE_URL}/analyze/video-async",
                files={"file": (filename, video_bytes, "video/mp4")},
            )
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        logger.error("Deepfake async submit error: %s", e)
    return {"module_unavailable": True}


async def poll_video_job(job_id: str) -> dict:
    """GET /analyze/status/{job_id}"""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            r = await client.get(f"{DEEPFAKE_URL}/analyze/status/{job_id}")
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        logger.error("Deepfake job poll error: %s", e)
    return {"status": "failed", "error": "Could not reach deepfake service"}


async def health_check() -> bool:
    """Quick health check — returns True if service is up."""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
            r = await client.get(f"{DEEPFAKE_URL}/health")
            return r.status_code == 200
    except Exception:
        return False


# ── Legacy wrapper ────────────────────────────────────────────────────────────
async def analyze_video(media_bytes: bytes, media_type: str = "video") -> dict:
    """Legacy wrapper for backward compatibility."""
    return await analyze_video_bytes(media_bytes)


# ── Formatting ─────────────────────────────────────────────────────────────────
def format_deepfake_report(result: dict, is_video: bool = False, human_explanation: str = "") -> str:
    score = result.get("overall_risk_score", 0)
    prob = result.get("ensemble_probability", 0.0)
    level = result.get("overall_risk_level", "Unknown")
    verdict = result.get("verdict", "UNKNOWN")
    face = result.get("face_info", {})
    quality = result.get("input_quality", {})
    message = result.get("message", "")
    flags = result.get("all_flags", [])

    # Risk badge
    risk_lower = level.lower()
    if "high" in risk_lower or "critical" in risk_lower:
        badge = "🚨 HIGH RISK"
    elif "medium" in risk_lower:
        badge = "⚠️ MEDIUM RISK"
    elif "low" in risk_lower:
        badge = "🟡 LOW RISK"
    else:
        badge = "✅ SAFE"

    lines = [
        "🛡️ Aegis AI — Deepfake Detection Report",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📊 Result: {verdict}",
        "",
    ]

    # Primary explanation: use service's message if available, else passed human explanation
    if message:
        lines.append(message)
    elif human_explanation:
        lines.append(human_explanation)
    else:
        lines.append(f"This { 'video' if is_video else 'image' } is {verdict.lower()} with {int(prob*100)}% confidence.")
    lines.append("")

    lines.append("🧠 AI Assessment:")
    lines.append(f"• Fake Probability: {int(prob*100)}%")
    lines.append(f"• Risk Level: {level}")
    lines.append(f"• Final Score: {score} / 100")
    lines.append("")

    lines.append("📷 Image Analysis:" if not is_video else "🎬 Video Analysis:")
    faces = face.get("faces_detected", 0)
    if faces:
        lines.append(f"• Faces Detected: {faces}")
        if face.get("multiple_faces"):
            lines.append("• Primary Analysis: Largest face selected")
    if quality.get("status"):
        lines.append(f"• Image Quality: {quality.get('status', 'Unknown').title()}")
    if quality.get("warnings"):
        first_warning = quality.get("warnings")[0]
        if len(first_warning) < 100:
            lines.append(f"• Note: {first_warning}")

    # Show only important flags (skip generic ones)
    skip_flags = {"detected", "analyzing", "primary analyzed", "ensemble", "model", "agreement"}
    important_flags = [f for f in flags if not any(skip in f.lower() for skip in skip_flags)]
    if important_flags:
        lines.append("")
        lines.append("⚠️ Signals:")
        for f in important_flags[:3]:
            lines.append(f"  • {f}")

    lines.append("")
    lines.append("🛡️ Aegis AI — Deepfake Detector")
    return "\n".join(lines)


def format_deepfake_image(result: dict, human_explanation: str = "") -> str:
    return format_deepfake_report(result, is_video=False, human_explanation=human_explanation)


def format_deepfake_video(result: dict, human_explanation: str = "") -> str:
    return format_deepfake_report(result, is_video=True, human_explanation=human_explanation)


def format_deepfake_result(result: dict, human_explanation: str = "") -> str:
    """Legacy compatibility wrapper."""
    return format_deepfake_report(result, is_video=False, human_explanation=human_explanation)


def format_deepfake_no_face(input_type: str = "image") -> str:
    return (
        f"👤 *No Face Detected*\n\n"
        f"The deepfake detector couldn't find a face in this {input_type}.\n\n"
        f"Deepfake analysis only works on images/videos containing human faces.\n"
        f"Please send a clear photo or video showing a person's face."
    )


def format_deepfake_job_submitted(job_id: str) -> str:
    return (
        f"🎬 *Video Analysis Submitted*\n\n"
        f"Job ID: `{job_id}`\n\n"
        f"⏱️ Video deepfake analysis takes 45–90 seconds.\n"
        f"Send `/deepfake-status {job_id}` to check the result.\n\n"
        f"I'll also notify you automatically when complete."
    )