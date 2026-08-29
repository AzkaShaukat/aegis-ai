"""
Image analysis pipeline — Phase 3.
Multi-face: analyze ALL detected faces individually, report each clearly.
Final verdict = highest-risk face (worst-case security).
"""
from __future__ import annotations
import logging, time, uuid
from datetime import date
from typing import Optional

import cv2, httpx, numpy as np

from app.config import get_settings
from app.models.ensemble import (
    EnsembleState, compute_ensemble_probability, compute_model_agreement, confidence_pct,
)
from app.schemas import (
    DeepfakeAnalysisResult, EnsembleWeights, FaceInfo,
    InputQuality, ModelAgreement, PerModelScores, Pipeline, RiskLevel,
)
from app.utils.face_detector import get_face_detector
from app.utils.preprocessing import apply_whatsapp_sharpening, preprocess_image_for_ensemble
from app.utils.quality_gate import run_quality_gate
from app.utils.redis_client import get_cached_image_result, set_cached_image_result

settings = get_settings()
logger = logging.getLogger(__name__)


def _p_to_risk(p: float) -> RiskLevel:
    s = int(p * 100)
    if s <= settings.RISK_CLEAN_MAX:  return RiskLevel.CLEAN
    if s <= settings.RISK_LOW_MAX:    return RiskLevel.LOW
    if s <= settings.RISK_MEDIUM_MAX: return RiskLevel.MEDIUM
    if s <= settings.RISK_HIGH_MAX:   return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _p_to_verdict(p: float) -> str:
    if p < 0.20: return "REAL"
    if p < 0.45: return "LIKELY_REAL"
    if p < 0.55: return "UNCERTAIN"
    if p < 0.80: return "LIKELY_FAKE"
    return "FAKE"


def _analyze_single_face(face_crop_bgr: np.ndarray, ensemble: EnsembleState) -> tuple:
    """Returns (p_fake, per_model, rule, conf)."""
    tensors = preprocess_image_for_ensemble(face_crop_bgr)
    if not ensemble.any_loaded:
        return 0.5, {"model_1": 0.5, "model_2": 0.5, "model_3": 0.5}, "Stub", 0.0
    return compute_ensemble_probability(ensemble, tensors, apply_sharpening=True)


def _error_result(scan_id, ensemble, msg) -> DeepfakeAnalysisResult:
    return DeepfakeAnalysisResult(
        scan_id=scan_id, scan_date=str(date.today()), pipeline_used=Pipeline.IMAGE,
        overall_risk_score=0, overall_risk_level=RiskLevel.CLEAN,
        ensemble_probability=0.0, confidence_score=0.0,
        verdict="UNAVAILABLE", message=f"⚠️ {msg}",
        confidence_note="Analysis could not be performed.",
        per_model_scores=PerModelScores(
            model_1_name="EfficientNet-B4", model_1_p_fake=0.0,
            model_2_name="ViT-B/16",        model_2_p_fake=0.0,
            model_3_name="FrequencyCNN",    model_3_p_fake=0.0,
        ),
        ensemble_weights=EnsembleWeights(
            model_1_weight=ensemble.weights[0], model_2_weight=ensemble.weights[1],
            model_3_weight=ensemble.weights[2], source=ensemble.weight_source,
        ),
        model_agreement=ModelAgreement.HIGH,
        face_info=FaceInfo(faces_detected=0, multiple_faces=False),
        input_quality=InputQuality(status="poor", blur_score=0.0,
                                   resolution_ok=False, face_visibility_ok=False,
                                   warnings=[msg]),
        all_flags=[msg], total_flags=1, elapsed_ms=0.0,
    )


def analyze_image(
    image_bytes: bytes,
    ensemble: EnsembleState,
    source_hint: Optional[str] = None,
    use_cache: bool = True,
    include_gradcam: bool = False,
) -> DeepfakeAnalysisResult:
    t_start = time.perf_counter()
    scan_id = f"img-{uuid.uuid4().hex[:12]}"

    # Cache lookup
    if use_cache and source_hint != "whatsapp":
        cached = get_cached_image_result(image_bytes)
        if cached:
            try:
                result = DeepfakeAnalysisResult(**cached)
                result.cached = True
                result.scan_id = scan_id
                return result
            except Exception:
                pass

    # Decode
    nparr = np.frombuffer(image_bytes, np.uint8)
    image_bgr = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if image_bgr is None:
        raise ValueError("Cannot decode image. Send JPEG, PNG, WebP, or BMP.")

    if source_hint == "whatsapp":
        image_bgr = apply_whatsapp_sharpening(image_bgr)

    # Quality gate (validates primary face)
    quality_result, primary_crop_bgr = run_quality_gate(image_bgr)
    if quality_result.errors or not quality_result.face_detected:
        return _error_result(
            scan_id, ensemble,
            quality_result.errors[0] if quality_result.errors else "No face detected."
        )

    # Detect ALL valid faces
    detector = get_face_detector()
    all_face_data = detector.detect_all_faces(image_bgr, target_size=224, padding=0.15)
    n_faces = len(all_face_data)

    if n_faces == 0:
        # Fallback to primary crop from quality gate
        rgb = cv2.cvtColor(primary_crop_bgr, cv2.COLOR_BGR2RGB)
        all_face_data = [(rgb, None)]
        n_faces = 1

    all_flags = list(quality_result.warnings)

    # ── Analyze each face independently ──────────────────────────────────
    face_results = []
    for idx, (face_rgb, face_obj) in enumerate(all_face_data):
        face_bgr = cv2.cvtColor(face_rgb, cv2.COLOR_RGB2BGR)
        p, per_m, rule, fc = _analyze_single_face(face_bgr, ensemble)
        face_results.append({
            "idx": idx + 1,
            "p_fake": p,
            "per_model": per_m,
            "rule": rule,
            "conf": fc,
            "verdict": _p_to_verdict(p),
        })

    # ── Build clear per-face report ───────────────────────────────────────
    if n_faces == 1:
        fr = face_results[0]
        p_fake    = fr["p_fake"]
        per_model = fr["per_model"]
        rule      = fr["rule"]
        conf      = fr["conf"]
        worst_idx = 1
    else:
        # Report EVERY face clearly
        all_flags.append(
            f"{'─'*50}\n"
            f"  {n_faces} faces detected in this image.\n"
            f"  Each face was analyzed independently:\n"
        )
        for fr in face_results:
            icon = {"REAL": "✅", "LIKELY_REAL": "🟡", "UNCERTAIN": "⚠️",
                    "LIKELY_FAKE": "🔴", "FAKE": "🚨"}.get(fr["verdict"], "❓")
            all_flags.append(
                f"  {icon} Face {fr['idx']}: {fr['p_fake']:.0%} fake "
                f"| Confidence {fr['conf']:.0f}% "
                f"| EfficientNet={fr['per_model'].get('model_1',0):.0%} "
                f"ViT={fr['per_model'].get('model_2',0):.0%} "
                f"FreqCNN={fr['per_model'].get('model_3',0):.0%} "
                f"→ {fr['verdict']}"
            )

        # Final = worst-case (highest p_fake)
        worst = max(face_results, key=lambda r: r["p_fake"])
        p_fake    = worst["p_fake"]
        per_model = worst["per_model"]
        rule      = worst["rule"]
        conf      = worst["conf"]
        worst_idx = worst["idx"]
        all_flags.append(
            f"{'─'*50}\n"
            f"  Final verdict based on Face {worst_idx} (highest risk)."
        )

    # GradCAM on worst-case face
    gradcam_b64 = None
    if include_gradcam and ensemble.model_1 is not None:
        try:
            from app.analyzers.gradcam import generate_gradcam_overlay
            bgr_for_cam = cv2.cvtColor(all_face_data[worst_idx-1][0], cv2.COLOR_RGB2BGR)
            tensors_gc = preprocess_image_for_ensemble(bgr_for_cam)
            gradcam_b64 = generate_gradcam_overlay(
                ensemble.model_1, bgr_for_cam, tensors_gc["standard"], ensemble.device
            )
        except Exception as e:
            logger.warning(f"GradCAM failed: {e}")

    # Model-level flags
    if p_fake > 0.55: all_flags.append(f"Ensemble: {p_fake:.0%} manipulation probability")
    if per_model.get("model_1", 0) > 0.60: all_flags.append("EfficientNet: texture/boundary artifacts")
    if per_model.get("model_2", 0) > 0.60: all_flags.append("ViT: structural inconsistencies")
    if per_model.get("model_3", 0) > 0.60: all_flags.append("FrequencyCNN: GAN noise in FFT spectrum")
    if quality_result.blur_score < settings.MIN_BLUR_SCORE:
        all_flags.append(f"Blurry image (score {quality_result.blur_score:.1f})")

    risk_level = _p_to_risk(p_fake)
    verdict    = _p_to_verdict(p_fake)
    risk_score = int(p_fake * 100)
    elapsed    = (time.perf_counter() - t_start) * 1000

    MESSAGES = {
        "REAL":        f"✅ REAL — No deepfake artifacts ({p_fake:.0%} fake | {conf:.0f}% confident)",
        "LIKELY_REAL": f"🟡 LIKELY REAL — Minor signals ({p_fake:.0%} fake | {conf:.0f}% confident)",
        "UNCERTAIN":   f"⚠️ UNCERTAIN — Inconclusive ({p_fake:.0%}). Manual review recommended.",
        "LIKELY_FAKE": f"🔴 LIKELY FAKE — Manipulation patterns ({p_fake:.0%} fake | {conf:.0f}% confident)",
        "FAKE":        f"🚨 FAKE — High-confidence deepfake ({p_fake:.0%} fake | {conf:.0f}% confident)",
    }

    face_note = f" (Face {worst_idx}/{n_faces})" if n_faces > 1 else ""
    scores_str = (
        f"EfficientNet={per_model.get('model_1',0):.0%} "
        f"ViT={per_model.get('model_2',0):.0%} "
        f"FreqCNN={per_model.get('model_3',0):.0%}"
    )

    all_faces_detected = detector.detect(image_bgr)
    primary_conf = all_faces_detected[0].confidence if all_faces_detected else None

    result = DeepfakeAnalysisResult(
        scan_id=scan_id, scan_date=str(date.today()), pipeline_used=Pipeline.IMAGE,
        overall_risk_score=risk_score, overall_risk_level=risk_level,
        ensemble_probability=round(p_fake, 4),
        confidence_score=round(conf, 1),
        verdict=verdict,
        message=MESSAGES.get(verdict, "Analysis complete"),
        confidence_note=(
            f"Ensemble: {p_fake:.0%} fake{face_note} | Confidence: {conf:.0f}% | "
            f"{scores_str} | {rule}"
            + (f" | Quality: {quality_result.status}" if quality_result.status != "good" else "")
        ),
        per_model_scores=PerModelScores(
            model_1_name="EfficientNet-B4",
            model_1_p_fake=round(per_model.get("model_1", 0), 4),
            model_2_name="ViT-B/16",
            model_2_p_fake=round(per_model.get("model_2", 0), 4),
            model_3_name="FrequencyCNN",
            model_3_p_fake=round(per_model.get("model_3", 0), 4),
        ),
        ensemble_weights=EnsembleWeights(
            model_1_weight=ensemble.weights[0],
            model_2_weight=ensemble.weights[1],
            model_3_weight=ensemble.weights[2],
            source=ensemble.weight_source,
        ),
        model_agreement=ModelAgreement(compute_model_agreement(per_model)),
        face_info=FaceInfo(
            faces_detected=n_faces,
            primary_face_size_px=quality_result.face_size_px,
            face_detection_confidence=primary_conf,
            multiple_faces=n_faces > 1,
        ),
        input_quality=InputQuality(
            status=quality_result.status,
            blur_score=round(quality_result.blur_score, 2),
            resolution_ok=quality_result.resolution_ok,
            face_visibility_ok=quality_result.visibility >= 0.05,
            warnings=quality_result.warnings,
        ),
        gradcam_heatmap=gradcam_b64,
        all_flags=all_flags, total_flags=len(all_flags),
        elapsed_ms=round(elapsed, 2),
    )

    if use_cache and not gradcam_b64 and n_faces == 1:
        try:
            set_cached_image_result(image_bytes, result.model_dump())
        except Exception:
            pass

    return result


async def analyze_image_from_url(
    url: str, ensemble: EnsembleState,
    source_hint: Optional[str] = None,
) -> DeepfakeAnalysisResult:
    async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT) as client:
        resp = await client.get(url, follow_redirects=True)
        resp.raise_for_status()
    return analyze_image(resp.content, ensemble, source_hint)
