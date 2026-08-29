"""
Video analysis pipeline — optimized for speed.

Speed optimizations:
  - Face detection every 5th frame, reuse last crop
  - Max 45 frames analyzed regardless of video length
  - No-overlap temporal sequences (step=seq_len)
  - Batch size 32 for spatial/SRM
  - VIDEO_FPS_EXTRACT=1 in config

Verdict logic (v2):
  - If ANY single model scores <= 60% fake probability, the result is
    capped at REAL / LIKELY_REAL with boosted confidence.
  - Only when ALL three models exceed 60% can the result escalate to
    UNCERTAIN / LIKELY_FAKE / FAKE.
"""
from __future__ import annotations
import logging, os, tempfile, time, uuid
from datetime import date
from typing import Optional, Callable

import cv2, numpy as np, torch

from app.config import get_settings
from app.models.ensemble import (
    EnsembleState, compute_model_agreement,
    sharpen_confidence, five_rule_ensemble, confidence_pct,
)
from app.schemas import (
    DeepfakeAnalysisResult, EnsembleWeights, FaceInfo,
    InputQuality, ModelAgreement, PerModelScores,
    Pipeline, RiskLevel, VideoInfo, TimelineEntry,
)
from app.utils.face_detector import get_face_detector
from app.utils.preprocessing import (
    apply_whatsapp_sharpening, extract_frames, normalize_imagenet,
)
from app.utils.quality_gate import run_quality_gate

settings = get_settings()
logger = logging.getLogger(__name__)

_DETECT_EVERY_N = 5    # run detector every Nth frame
_MAX_FRAMES     = 45   # hard cap — enough for reliable analysis

# Any model at or below this threshold triggers the "real" override
_REAL_OVERRIDE_THRESHOLD = 0.60


def _p_to_risk(p):
    s = int(p * 100)
    if s <= settings.RISK_CLEAN_MAX:  return RiskLevel.CLEAN
    if s <= settings.RISK_LOW_MAX:    return RiskLevel.LOW
    if s <= settings.RISK_MEDIUM_MAX: return RiskLevel.MEDIUM
    if s <= settings.RISK_HIGH_MAX:   return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def _p_to_verdict(p):
    if p < 0.20: return "REAL"
    if p < 0.45: return "LIKELY_REAL"
    if p < 0.55: return "UNCERTAIN"
    if p < 0.80: return "LIKELY_FAKE"
    return "FAKE"


def _apply_real_override(p_sp: float, p_tm: float, p_srm: float,
                         p_fake: float, conf: float):
    """
    If any single model verdict is <= _REAL_OVERRIDE_THRESHOLD (60%),
    override the ensemble result toward REAL / LIKELY_REAL.

    Returns (p_fake_adjusted, conf_adjusted, override_applied, note).
    """
    lowest_model_score = min(p_sp, p_tm, p_srm)

    if lowest_model_score > _REAL_OVERRIDE_THRESHOLD:
        # All models exceed 60% — no override, let ensemble decide
        return p_fake, conf, False, None

    # --- Override logic ---
    # Scale the adjusted p_fake based on how far below 60% the lowest score is.
    # A score of 0.00 → adjusted p_fake = 0.05 (very confident REAL)
    # A score of 0.60 → adjusted p_fake = 0.40 (LIKELY_REAL boundary)
    ratio = lowest_model_score / _REAL_OVERRIDE_THRESHOLD   # 0.0 – 1.0
    p_adjusted = 0.05 + ratio * 0.35   # maps [0, 0.60] → [0.05, 0.40]

    # Confidence reflects how convincingly below the threshold the model is
    conf_boost = (1.0 - ratio) * 30    # up to +30 points when score is near 0
    conf_adjusted = min(99.0, conf + conf_boost + 10.0)

    note = (
        f"Real-override active: lowest model score {lowest_model_score:.0%} "
        f"<= {_REAL_OVERRIDE_THRESHOLD:.0%} threshold — "
        f"result capped at LIKELY_REAL or better."
    )
    return p_adjusted, conf_adjusted, True, note


def _preprocess_frames(face_crops_rgb):
    tensors = []
    for rgb in face_crops_rgb:
        chw = normalize_imagenet(cv2.resize(rgb, (224, 224)))
        tensors.append(torch.from_numpy(chw))
    return torch.stack(tensors) if tensors else torch.zeros(0, 3, 224, 224)


def _build_sequences(face_crops_rgb, seq_len=16):
    if not face_crops_rgb:
        return []
    mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
    std  = np.array([0.229, 0.224, 0.225], dtype=np.float32)
    frames = []
    for rgb in face_crops_rgb:
        f = cv2.resize(rgb, (112, 112)).astype(np.float32) / 255.0
        f = (f - mean) / std
        frames.append(torch.from_numpy(f.transpose(2, 0, 1)))
    if len(frames) < seq_len:
        frames += [frames[-1]] * (seq_len - len(frames))
    seqs = []
    for start in range(0, len(frames) - seq_len + 1, seq_len):  # no overlap
        seqs.append(torch.stack(frames[start:start + seq_len]))
    return seqs


@torch.no_grad()
def _run_spatial(model, tensor, device):
    if model is None or tensor.shape[0] == 0:
        return 0.5
    model.eval()
    probs = []
    for i in range(0, tensor.shape[0], 32):
        out = model(tensor[i:i+32].to(device))
        if out.dim() > 1: out = out.squeeze(1)
        probs.extend(torch.sigmoid(out).cpu().tolist())
    return float(np.nanmean(probs)) if probs else 0.5


@torch.no_grad()
def _run_temporal(model, sequences, device):
    if model is None or not sequences:
        return 0.5
    model.eval()
    probs = []
    for i in range(0, len(sequences), 4):
        batch = torch.stack(sequences[i:i+4]).to(device)
        out = model(batch)
        if out.dim() > 1: out = out.squeeze(1)
        probs.extend(torch.sigmoid(out).cpu().tolist())
    return float(np.nanmean(probs)) if probs else 0.5


def _error_result(scan_id, ensemble, msg):
    return DeepfakeAnalysisResult(
        scan_id=scan_id, scan_date=str(date.today()), pipeline_used=Pipeline.VIDEO,
        overall_risk_score=0, overall_risk_level=RiskLevel.CLEAN,
        ensemble_probability=0.0, confidence_score=0.0,
        verdict="UNAVAILABLE", message=f"⚠️ {msg}",
        confidence_note="Analysis could not be performed.",
        per_model_scores=PerModelScores(
            model_1_name="Spatial CNN", model_1_p_fake=0.0,
            model_2_name="Temporal Transformer", model_2_p_fake=0.0,
            model_3_name="Frequency SRM CNN", model_3_p_fake=0.0,
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


def analyze_video(
    video_bytes: bytes,
    ensemble: EnsembleState,
    source_hint: Optional[str] = None,
    include_timeline: bool = False,
    progress_callback: Optional[Callable[[str, str], None]] = None,
) -> DeepfakeAnalysisResult:
    t_start = time.perf_counter()
    scan_id = f"vid-{uuid.uuid4().hex[:12]}"

    def _prog(status, msg):
        if progress_callback: progress_callback(status, msg)

    _prog("preprocessing", "Saving video...")
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tf:
        tf.write(video_bytes)
        tmp_path = tf.name

    try:
        _prog("extracting_faces", "Extracting frames...")
        raw_frames = list(extract_frames(tmp_path, fps_target=settings.VIDEO_FPS_EXTRACT))
    except Exception as e:
        try: os.unlink(tmp_path)
        except: pass
        return _error_result(scan_id, ensemble, f"Could not read video: {e}")
    finally:
        try: os.unlink(tmp_path)
        except: pass

    if not raw_frames:
        return _error_result(scan_id, ensemble, "No frames extracted from video.")

    if source_hint == "whatsapp":
        raw_frames = [apply_whatsapp_sharpening(f) for f in raw_frames]

    # Cap frames with even sampling
    if len(raw_frames) > _MAX_FRAMES:
        idx = [int(i * len(raw_frames) / _MAX_FRAMES) for i in range(_MAX_FRAMES)]
        raw_frames = [raw_frames[i] for i in idx]

    # Face detection — every Nth frame, reuse last crop
    _prog("extracting_faces", f"Face detection ({len(raw_frames)} frames)...")
    detector = get_face_detector()
    face_crops_rgb, frames_with_face = [], 0
    last_crop = None

    for idx, frame_bgr in enumerate(raw_frames):
        if idx % _DETECT_EVERY_N == 0:
            crop_rgb, _ = detector.detect_and_crop_primary(frame_bgr, target_size=224)
            if crop_rgb is not None:
                last_crop = crop_rgb
        if last_crop is not None:
            face_crops_rgb.append(last_crop)
            frames_with_face += 1

    face_detection_rate = frames_with_face / len(raw_frames) if raw_frames else 0.0

    if not face_crops_rgb:
        return _error_result(
            scan_id, ensemble,
            "No face detected in this video. Send a video with a clearly visible human face."
        )

    # Quality gate
    first_bgr = cv2.cvtColor(cv2.resize(face_crops_rgb[0], (224, 224)), cv2.COLOR_RGB2BGR)
    quality_result, _ = run_quality_gate(first_bgr)

    # Reject non-face content in video too
    if quality_result.errors and not quality_result.face_detected:
        return _error_result(scan_id, ensemble, quality_result.errors[0])

    all_flags = list(quality_result.warnings)

    _prog("running_models", "Running ensemble inference...")
    spatial_tensor = _preprocess_frames(face_crops_rgb)
    temporal_seqs  = _build_sequences(face_crops_rgb, seq_len=settings.SEQUENCE_LENGTH)
    device = ensemble.device

    if not ensemble.any_loaded:
        p_sp = p_tm = p_srm = 0.5
    else:
        p_sp  = _run_spatial(ensemble.model_1, spatial_tensor, device)
        p_tm  = _run_temporal(ensemble.model_2, temporal_seqs, device)
        p_srm = _run_spatial(ensemble.model_3, spatial_tensor, device)

    per_model = {"model_1": p_sp, "model_2": p_tm, "model_3": p_srm}
    w = ensemble.weights
    p_raw, rule = five_rule_ensemble(p_sp, p_tm, p_srm, w[0], w[1], w[2])
    p_fake = sharpen_confidence(p_raw)
    conf   = confidence_pct(p_fake)
    agreement = compute_model_agreement(per_model)

    # ------------------------------------------------------------------ #
    #  Real-override: if ANY model score is <= 60%, cap toward REAL       #
    # ------------------------------------------------------------------ #
    p_fake, conf, override_applied, override_note = _apply_real_override(
        p_sp, p_tm, p_srm, p_fake, conf
    )
    if override_note:
        all_flags.append(override_note)

    # ------------------------------------------------------------------ #

    timeline = None
    if include_timeline and ensemble.model_1 is not None:
        timeline = []
        fps = settings.VIDEO_FPS_EXTRACT
        for i in range(0, len(face_crops_rgb), max(1, fps)):
            try:
                t = torch.from_numpy(normalize_imagenet(
                    cv2.resize(face_crops_rgb[i], (224, 224))
                )).unsqueeze(0).to(device)
                with torch.no_grad():
                    out = ensemble.model_1(t)
                    if out.dim() > 1: out = out.squeeze(1)
                    p = float(torch.sigmoid(out).item())
            except Exception:
                p = 0.5
            timeline.append(TimelineEntry(second=i // max(1, fps), p_fake=round(p, 4)))

    # Flags — only raise fake-side flags when the override is NOT active
    if not override_applied:
        if p_fake > 0.55: all_flags.append(f"Ensemble: {p_fake:.0%} manipulation probability")
        if p_tm   > 0.55: all_flags.append("Temporal: inter-frame blinking/jitter/flickering")
        if p_sp   > 0.60: all_flags.append("Spatial: per-frame texture artifacts")
        if p_srm  > 0.60: all_flags.append("SRM: noise residuals or GAN fingerprints")

    if face_detection_rate < 0.5:
        all_flags.append(f"Face detected in only {face_detection_rate:.0%} of frames")

    elapsed    = (time.perf_counter() - t_start) * 1000
    risk_level = _p_to_risk(p_fake)
    verdict    = _p_to_verdict(p_fake)

    MESSAGES = {
        "REAL":        f"✅ REAL ({p_fake:.0%} fake | {conf:.0f}% confident)",
        "LIKELY_REAL": f"🟡 LIKELY REAL ({p_fake:.0%} fake | {conf:.0f}% confident)",
        "UNCERTAIN":   f"⚠️ UNCERTAIN ({p_fake:.0%}). Manual review recommended.",
        "LIKELY_FAKE": f"🔴 LIKELY FAKE ({p_fake:.0%} fake | {conf:.0f}% confident)",
        "FAKE":        f"🚨 FAKE — Deepfake detected ({p_fake:.0%} | {conf:.0f}% confident)",
    }

    # Build confidence note — include override info when active
    raw_scores_note = (
        f"Raw scores — Spatial={p_sp:.0%} Temporal={p_tm:.0%} SRM={p_srm:.0%}"
    )
    override_tag = " [real-override]" if override_applied else ""
    confidence_note = (
        f"Ensemble: {p_fake:.0%} | Confidence: {conf:.0f}%{override_tag} | "
        f"{raw_scores_note} | "
        f"{rule} | {len(raw_frames)} frames, {len(temporal_seqs)} seqs, agreement={agreement}"
    )

    return DeepfakeAnalysisResult(
        scan_id=scan_id, scan_date=str(date.today()), pipeline_used=Pipeline.VIDEO,
        overall_risk_score=int(p_fake*100), overall_risk_level=risk_level,
        ensemble_probability=round(p_fake, 4), confidence_score=round(conf, 1),
        verdict=verdict, message=MESSAGES.get(verdict, "Analysis complete"),
        confidence_note=confidence_note,
        per_model_scores=PerModelScores(
            model_1_name="Spatial CNN",          model_1_p_fake=round(p_sp,  4),
            model_2_name="Temporal Transformer", model_2_p_fake=round(p_tm,  4),
            model_3_name="Frequency SRM CNN",    model_3_p_fake=round(p_srm, 4),
        ),
        ensemble_weights=EnsembleWeights(
            model_1_weight=w[0], model_2_weight=w[1], model_3_weight=w[2],
            source=ensemble.weight_source,
        ),
        model_agreement=ModelAgreement(agreement),
        face_info=FaceInfo(
            faces_detected=1, primary_face_size_px=quality_result.face_size_px,
            multiple_faces=False,
        ),
        input_quality=InputQuality(
            status=quality_result.status, blur_score=round(quality_result.blur_score, 2),
            resolution_ok=quality_result.resolution_ok, face_visibility_ok=True,
            warnings=quality_result.warnings,
        ),
        video_info=VideoInfo(
            duration_seconds=round(len(raw_frames)/max(1,settings.VIDEO_FPS_EXTRACT), 1),
            fps_extracted=settings.VIDEO_FPS_EXTRACT,
            total_frames_extracted=len(raw_frames),
            sequences_analyzed=len(temporal_seqs),
            face_detection_rate=round(face_detection_rate, 3),
        ),
        timeline=timeline, all_flags=all_flags, total_flags=len(all_flags),
        elapsed_ms=round(elapsed, 2),
    )