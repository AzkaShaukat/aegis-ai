"""
tamper_detector.py — Phase 2, Feature 2.1
Physical QR Tamper Detector

Detects when a malicious sticker has been placed over a legitimate QR code.
This is how ATM, restaurant, parking meter, and bus-stop QR attacks work.

Detection techniques:
  1. Quiet zone uniformity (sticker disrupts the white border)
  2. Shadow/edge line analysis (sticker edges cast micro-shadows)
  3. Multi-region brightness inconsistency (sticker reflects light differently)
  4. Compression artifact variance (sticker in photo = two JPEG compression layers)
  5. Color channel asymmetry (genuine printed QRs are pure black/white)
"""

import cv2
import numpy as np
from PIL import Image
from app.logger import log


def _pil_to_bgr(pil_image: Image.Image) -> np.ndarray:
    arr = np.array(pil_image.convert("RGB"))
    return arr[:, :, ::-1].copy()


# ─────────────────────────────────────────────────────────────
# Technique 1 — Quiet Zone Uniformity
# ─────────────────────────────────────────────────────────────

def _check_quiet_zone(gray: np.ndarray) -> dict:
    """
    The quiet zone (white border) of a genuine QR must be uniform white.
    A sticker disrupts this: part of the border comes from the sticker edges
    and part from the original print, creating contrast differences.
    """
    h, w = gray.shape
    margin = max(4, min(h, w) // 20)

    zones = {
        "top":    gray[:margin, :],
        "bottom": gray[h-margin:, :],
        "left":   gray[:, :margin],
        "right":  gray[:, w-margin:]
    }

    suspicious = []
    for name, zone in zones.items():
        std = float(np.std(zone))
        mean = float(np.mean(zone))
        # Healthy quiet zone: high mean (white) + low std (uniform)
        # Compromised quiet zone: variable brightness
        if std > 45:
            suspicious.append({
                "zone": name,
                "std": round(std, 2),
                "mean": round(mean, 2),
                "note": f"High variance in {name} quiet zone (std={std:.1f} > 45)"
            })

    confidence = min(1.0, len(suspicious) / 4 * 1.5)
    return {
        "technique": "quiet_zone_uniformity",
        "suspicious": len(suspicious) >= 2,
        "confidence": round(confidence, 3),
        "findings": suspicious
    }


# ─────────────────────────────────────────────────────────────
# Technique 2 — Sticker Edge Line Detection
# ─────────────────────────────────────────────────────────────

def _check_edge_lines(gray: np.ndarray) -> dict:
    """
    Stickers create a sharp rectangular shadow line around their perimeter.
    These show up as long straight horizontal/vertical lines in edge detection
    that don't correspond to the QR code pattern itself (which has short segments).
    """
    h, w = gray.shape
    min_line_length = min(h, w) // 2   # Lines must span at least half the image
    min_line_pixels = min(h, w) // 3

    edges = cv2.Canny(gray, 30, 120)
    # Detect straight lines longer than half the image dimension
    lines = cv2.HoughLinesP(
        edges, rho=1, theta=np.pi/180,
        threshold=80, minLineLength=min_line_pixels, maxLineGap=15
    )

    long_lines = []
    if lines is not None:
        for line in lines:
            x1, y1, x2, y2 = line[0]
            length = np.sqrt((x2-x1)**2 + (y2-y1)**2)
            # Long lines parallel to image edges (horizontal/vertical only)
            angle = abs(np.degrees(np.arctan2(y2-y1, x2-x1)))
            is_horizontal = angle < 10 or angle > 170
            is_vertical = 80 < angle < 100
            if length > min_line_length and (is_horizontal or is_vertical):
                long_lines.append({
                    "length": round(float(length), 1),
                    "angle": round(float(angle), 1),
                    "orientation": "horizontal" if is_horizontal else "vertical"
                })

    # More than 6 long edge-parallel lines = suspicious
    suspicious = len(long_lines) > 6
    confidence = min(1.0, len(long_lines) / 12)

    return {
        "technique": "sticker_edge_lines",
        "suspicious": suspicious,
        "confidence": round(confidence, 3),
        "long_parallel_lines": len(long_lines),
        "threshold": 6,
        "sample_lines": long_lines[:5]
    }


# ─────────────────────────────────────────────────────────────
# Technique 3 — Multi-Region Brightness Inconsistency
# ─────────────────────────────────────────────────────────────

def _check_region_brightness(gray: np.ndarray) -> dict:
    """
    Divides the image into a 3x3 grid and checks brightness consistency.
    A sticker on part of the image creates a brightness discontinuity:
    the sticker surface reflects light differently than the background.
    """
    h, w = gray.shape
    rh, rw = h // 3, w // 3

    region_means = []
    for row in range(3):
        for col in range(3):
            region = gray[row*rh:(row+1)*rh, col*rw:(col+1)*rw]
            region_means.append(float(np.mean(region)))

    overall_std = float(np.std(region_means))
    # Uniform image = low std. Sticker creates a brightness discontinuity.
    suspicious = overall_std > 40

    return {
        "technique": "region_brightness",
        "suspicious": suspicious,
        "confidence": round(min(1.0, overall_std / 80), 3),
        "region_std": round(overall_std, 2),
        "threshold": 40,
        "region_means": [round(m, 1) for m in region_means]
    }


# ─────────────────────────────────────────────────────────────
# Technique 4 — JPEG Compression Artifact Inconsistency
# ─────────────────────────────────────────────────────────────

def _check_compression_artifacts(gray: np.ndarray) -> dict:
    """
    When a sticker photo is taken, two JPEG compressions exist:
    1. The original background print
    2. The sticker print (different compression settings/generation)
    This creates locally inconsistent DCT block variance patterns.
    We analyze 8x8 block variance distribution for anomalies.
    """
    h, w = gray.shape
    block_size = 8
    variances = []

    for y in range(0, h - block_size, block_size):
        for x in range(0, w - block_size, block_size):
            block = gray[y:y+block_size, x:x+block_size].astype(float)
            variances.append(float(np.var(block)))

    if not variances:
        return {"technique": "compression_artifacts", "suspicious": False, "confidence": 0.0}

    var_array = np.array(variances)
    # High variance OF variances = inconsistent compression regions
    meta_std = float(np.std(var_array))
    # If some blocks are very smooth and some very noisy = two different sources
    q75 = float(np.percentile(var_array, 75))
    q25 = float(np.percentile(var_array, 25))
    iqr = q75 - q25

    suspicious = meta_std > 2500 and iqr > 1000

    return {
        "technique": "compression_artifacts",
        "suspicious": suspicious,
        "confidence": round(min(1.0, meta_std / 5000), 3),
        "block_variance_std": round(meta_std, 1),
        "iqr": round(iqr, 1),
        "threshold_std": 2500
    }


# ─────────────────────────────────────────────────────────────
# Technique 5 — Color Channel Asymmetry
# ─────────────────────────────────────────────────────────────

def _check_color_asymmetry(bgr: np.ndarray) -> dict:
    """
    Genuine printed QR codes are pure black/white — R=G=B everywhere.
    A color photo of a sticker may show slight color casts from:
    - Sticker glossy surface reflecting ambient light differently
    - Camera white balance affecting sticker vs background differently
    If R, G, B channels differ significantly in std deviation, it's suspicious.
    """
    b, g, r = cv2.split(bgr)

    r_std = float(np.std(r))
    g_std = float(np.std(g))
    b_std = float(np.std(b))

    # Max difference between channels
    channel_stds = [r_std, g_std, b_std]
    max_diff = max(channel_stds) - min(channel_stds)

    # Large difference = color imbalance = possible sticker
    suspicious = max_diff > 25

    return {
        "technique": "color_asymmetry",
        "suspicious": suspicious,
        "confidence": round(min(1.0, max_diff / 50), 3),
        "channel_std": {"r": round(r_std, 2), "g": round(g_std, 2), "b": round(b_std, 2)},
        "max_channel_diff": round(max_diff, 2),
        "threshold": 25
    }


# ─────────────────────────────────────────────────────────────
# PUBLIC
# ─────────────────────────────────────────────────────────────

def detect_physical_tamper(image: Image.Image) -> dict:
    """
    Runs all 5 tamper detection techniques on an image.

    Returns:
    {
        "tamper_suspected": bool,
        "confidence": float (0.0 - 1.0),
        "techniques_triggered": int,
        "findings": [dict per technique],
        "risk_score": int (0-100),
        "recommendation": str
    }
    """
    try:
        bgr = _pil_to_bgr(image)
        gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    except Exception as e:
        log.error(f"[Tamper] Image conversion failed: {e}")
        return {
            "tamper_suspected": False,
            "confidence": 0.0,
            "techniques_triggered": 0,
            "findings": [],
            "risk_score": 0,
            "error": str(e)
        }

    techniques = [
        _check_quiet_zone(gray),
        _check_edge_lines(gray),
        _check_region_brightness(gray),
        _check_compression_artifacts(gray),
        _check_color_asymmetry(bgr),
    ]

    triggered = [t for t in techniques if t.get("suspicious")]
    triggered_count = len(triggered)

    # Need at least 2 techniques to agree to avoid false positives
    tamper_suspected = triggered_count >= 2

    # Weighted confidence — average of triggered technique confidences
    if triggered:
        avg_confidence = sum(t.get("confidence", 0) for t in triggered) / len(triggered)
    else:
        avg_confidence = 0.0

    # Risk score: 0-100
    risk_score = min(100, triggered_count * 20 + int(avg_confidence * 30))

    if tamper_suspected:
        recommendation = (
            "🚨 POSSIBLE TAMPER: This QR code may have a sticker placed over it. "
            "Do not scan/connect. Report to venue staff and verify the original QR."
        )
    elif triggered_count == 1:
        technique_name = triggered[0]["technique"].replace("_", " ").title()
        recommendation = (
            f"⚠️ MINOR SIGNAL: One technique flagged ({technique_name}). "
            "Likely a false positive — single indicators are common in real-world photos. "
            "No action required unless combined with other suspicious signs."
        )
    else:
        recommendation = "✅ No tampering indicators detected in image analysis."

    if tamper_suspected:
        log.warning(
            f"[Tamper] Tamper suspected — {triggered_count}/5 techniques triggered, "
            f"confidence={avg_confidence:.2f}"
        )

    return {
        "tamper_suspected":    tamper_suspected,
        "confidence":          round(avg_confidence, 3),
        "techniques_triggered": triggered_count,
        "techniques_total":    5,
        "findings":            techniques,
        "triggered_techniques": [t["technique"] for t in triggered],
        "risk_score":          risk_score,
        "recommendation":      recommendation
    }
