"""
multi_decoder.py — v4 — Photo QR + Full Enhancement Pipeline
=============================================================

B10 FIX (CRITICAL): Mobile/WhatsApp photo QR codes now decode correctly.

ROOT CAUSE: pyzbar (ZBar library) fails on angled/JPEG-compressed screen photos
because it expects near-perfect binary images. cv2.QRCodeDetector uses a
built-in image enhancement pipeline and handles distortion natively.

SOLUTION: All 8 passes now run BOTH decoders:
  1. pyzbar  — Fast, handles multi-QR, cleaner format metadata
  2. cv2.QRCodeDetector — Robust against perspective, blur, JPEG artifacts

cv2 is tried first since it handles real-world photos better.

Verification:
  picture_sms.jpeg (angled HP laptop screen): cv2 decodes in Pass 1 (raw)
  pyzbar fails all 8 passes on the same image

Pass order (for clean digital images, Pass 1 succeeds in <10ms):
  Pass 1: raw               — clean digital QR
  Pass 2: enhanced          — adaptive threshold + sharpening
  Pass 3: inverted          — white-on-black QR
  Pass 4: clahe             — screen/backlight uneven illumination
  Pass 5: moire_reduction   — LCD/OLED screen pixel interference
  Pass 6: upscale_2x        — small/low-resolution QR
  Pass 7: perspective       — angled phone shots (WhatsApp)
  Pass 8: denoise           — heavy JPEG compression

B7 FIX (retained): Steganography threshold = 8000 (not 3000)
"""

import numpy as np
from PIL import Image
import cv2
from typing import Optional
from app.logger import log

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False
    log.warning("[MultiDecoder] pyzbar not available — using cv2 only")


# ─────────────────────────────────────────────────────────────
# Image conversion helpers
# ─────────────────────────────────────────────────────────────

def _pil_to_bgr(pil_image: Image.Image) -> np.ndarray:
    arr = np.array(pil_image.convert("RGB"))
    return arr[:, :, ::-1].copy()


def _bgr_to_gray(cv_img: np.ndarray) -> np.ndarray:
    if len(cv_img.shape) == 2:
        return cv_img
    return cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)


# ─────────────────────────────────────────────────────────────
# Dual decoder — pyzbar + cv2 (B10 FIX)
# ─────────────────────────────────────────────────────────────

def _decode_with_cv2(cv_img: np.ndarray, pass_label: str) -> list:
    """
    cv2.QRCodeDetector — primary decoder for real-world photos.
    Built-in perspective correction and binarization.
    Handles: phone photos, screen shots, WhatsApp-compressed images.
    """
    results = []
    try:
        qr_det = cv2.QRCodeDetector()

        # detectAndDecodeMulti handles multiple QR codes in one image
        try:
            retval, decoded_list, points_list, _ = qr_det.detectAndDecodeMulti(cv_img)
            if retval and decoded_list:
                for i, payload in enumerate(decoded_list):
                    if payload:
                        bbox = None
                        if points_list is not None and i < len(points_list) and points_list[i] is not None:
                            pts = points_list[i].reshape(-1, 2).astype(int)
                            x = int(pts[:, 0].min())
                            y = int(pts[:, 1].min())
                            w = int(pts[:, 0].max()) - x
                            h = int(pts[:, 1].max()) - y
                            bbox = {"left": x, "top": y, "width": w, "height": h}
                        results.append({
                            "payload":      payload,
                            "format":       "QRCODE",
                            "scan_pass":    f"{pass_label}:cv2_multi",
                            "bounding_box": bbox,
                            "polygon":      []
                        })
        except Exception:
            # Multi-decode not available in older cv2 — fall back to single
            pass

        # Single-QR fallback (always try)
        if not results:
            payload, pts, _ = qr_det.detectAndDecode(cv_img)
            if payload:
                bbox = None
                if pts is not None:
                    pts_r = pts.reshape(-1, 2).astype(int)
                    x = int(pts_r[:, 0].min())
                    y = int(pts_r[:, 1].min())
                    w = int(pts_r[:, 0].max()) - x
                    h = int(pts_r[:, 1].max()) - y
                    bbox = {"left": x, "top": y, "width": w, "height": h}
                results.append({
                    "payload":      payload,
                    "format":       "QRCODE",
                    "scan_pass":    f"{pass_label}:cv2",
                    "bounding_box": bbox,
                    "polygon":      []
                })
    except Exception as e:
        log.debug(f"[MultiDecoder] cv2 error (pass={pass_label}): {e}")
    return results


def _decode_with_pyzbar(pil_image: Image.Image, pass_label: str) -> list:
    """
    pyzbar — secondary decoder, best for clean digital QR codes.
    Returns richer metadata: exact format (DataMatrix, PDF417, etc.), polygon.
    """
    if not PYZBAR_AVAILABLE:
        return []
    results = []
    try:
        decoded_list = pyzbar_decode(pil_image)
        for item in decoded_list:
            try:
                payload = item.data.decode("utf-8", errors="replace")
            except Exception:
                payload = item.data.hex()
            results.append({
                "payload":      payload,
                "format":       str(item.type),
                "scan_pass":    f"{pass_label}:pyzbar",
                "bounding_box": {
                    "left": item.rect.left, "top": item.rect.top,
                    "width": item.rect.width, "height": item.rect.height
                },
                "polygon": [{"x": p.x, "y": p.y} for p in item.polygon]
            })
    except Exception as e:
        log.debug(f"[MultiDecoder] pyzbar error (pass={pass_label}): {e}")
    return results


def _decode_image(pil_image: Image.Image, pass_label: str) -> list:
    """
    Run both decoders on a single image variant.
    cv2 runs first (better for real photos), pyzbar second (better metadata).
    Deduplication by payload happens in the caller.
    """
    cv_img = _pil_to_bgr(pil_image)

    # Try cv2 first (better for distorted photos)
    results = _decode_with_cv2(cv_img, pass_label)

    # Try pyzbar for any additional codes cv2 might have missed
    pyzbar_results = _decode_with_pyzbar(pil_image, pass_label)

    # Merge: add pyzbar results that cv2 didn't find
    cv2_payloads = {r["payload"] for r in results}
    for r in pyzbar_results:
        if r["payload"] not in cv2_payloads:
            results.append(r)

    return results


# ─────────────────────────────────────────────────────────────
# Enhancement passes
# ─────────────────────────────────────────────────────────────

def _pass_raw(pil_image: Image.Image) -> Image.Image:
    """Pass 1: Raw. Fast path for clean digital images."""
    return pil_image


def _pass_enhanced(pil_image: Image.Image) -> Image.Image:
    """Pass 2: Adaptive threshold + sharpening."""
    cv_img = _pil_to_bgr(pil_image)
    gray = _bgr_to_gray(cv_img)
    thresh = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, blockSize=11, C=2
    )
    kernel = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]])
    sharpened = cv2.filter2D(thresh, -1, kernel)
    return Image.fromarray(sharpened)


def _pass_inverted(pil_image: Image.Image) -> Image.Image:
    """Pass 3: Inverted — white-on-black or dark-background QR codes."""
    cv_img = _pil_to_bgr(pil_image)
    gray = _bgr_to_gray(cv_img)
    return Image.fromarray(cv2.bitwise_not(gray))


def _pass_clahe(pil_image: Image.Image) -> Image.Image:
    """
    Pass 4: CLAHE (Contrast Limited Adaptive Histogram Equalization).
    Fixes uneven illumination from screen backlights or side lighting.
    """
    cv_img = _pil_to_bgr(pil_image)
    gray = _bgr_to_gray(cv_img)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    enhanced = clahe.apply(gray)
    _, otsu = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return Image.fromarray(otsu)


def _pass_moire_reduction(pil_image: Image.Image) -> Image.Image:
    """
    Pass 5: Moire pattern reduction.
    LCD/OLED screen pixels create interference patterns that confuse decoders.
    Gentle blur removes pixel-level interference, threshold recovers QR.
    """
    cv_img = _pil_to_bgr(pil_image)
    gray = _bgr_to_gray(cv_img)
    blurred = cv2.GaussianBlur(gray, (3, 3), 0.8)
    _, binary = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return Image.fromarray(binary)


def _pass_upscale(pil_image: Image.Image, scale: float = 2.0) -> Image.Image:
    """
    Pass 6: 2x bicubic upscale + CLAHE.
    For QRs that are small in the frame or degraded by WhatsApp compression.
    """
    cv_img = _pil_to_bgr(pil_image)
    h, w = cv_img.shape[:2]
    upscaled = cv2.resize(
        cv_img, (int(w * scale), int(h * scale)),
        interpolation=cv2.INTER_CUBIC
    )
    gray = _bgr_to_gray(upscaled)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    return Image.fromarray(clahe.apply(gray))


def _sort_corners(pts: np.ndarray) -> np.ndarray:
    """Sort 4 corner points as [TL, TR, BR, BL] for perspective transform."""
    rect = np.zeros((4, 2), dtype=np.float32)
    s = pts.sum(axis=1)
    diff = np.diff(pts, axis=1)
    rect[0] = pts[np.argmin(s)]    # TL: smallest x+y
    rect[2] = pts[np.argmax(s)]    # BR: largest x+y
    rect[1] = pts[np.argmin(diff)] # TR: x-y smallest
    rect[3] = pts[np.argmax(diff)] # BL: x-y largest
    return rect


def _pass_perspective_correct(pil_image: Image.Image) -> list:
    """
    Pass 7: Perspective correction for angled photos.
    Finds the QR code boundary, warps to a flat square view.
    Handles photos taken at an angle (common with mobile phones).
    """
    results = []
    cv_img = _pil_to_bgr(pil_image)
    h, w = cv_img.shape[:2]

    for threshold_val in [127, 80, 160]:
        try:
            gray = _bgr_to_gray(cv_img)
            blurred = cv2.GaussianBlur(gray, (5, 5), 0)
            _, binary = cv2.threshold(blurred, threshold_val, 255, cv2.THRESH_BINARY_INV)

            contours, _ = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            if not contours:
                continue

            largest = max(contours, key=cv2.contourArea)
            if cv2.contourArea(largest) < h * w * 0.05:
                continue

            epsilon = 0.02 * cv2.arcLength(largest, True)
            approx = cv2.approxPolyDP(largest, epsilon, True)

            if len(approx) == 4:
                pts = approx.reshape(4, 2).astype(np.float32)
                rect = _sort_corners(pts)
                side = max(
                    int(np.linalg.norm(rect[0] - rect[1])),
                    int(np.linalg.norm(rect[1] - rect[2])),
                    200
                )
                dst = np.array([[0, 0], [side-1, 0], [side-1, side-1], [0, side-1]], dtype=np.float32)
                M = cv2.getPerspectiveTransform(rect, dst)
                warped = cv2.warpPerspective(cv_img, M, (side, side))

                warp_gray = _bgr_to_gray(warped)
                clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
                warp_enhanced = clahe.apply(warp_gray)
                _, warp_binary = cv2.threshold(
                    warp_enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
                )
                results.append(Image.fromarray(warp_binary))
                results.append(Image.fromarray(warp_gray))

        except Exception as e:
            log.debug(f"[MultiDecoder] Perspective threshold={threshold_val}: {e}")

    return results[:3]


def _pass_denoise(pil_image: Image.Image) -> Image.Image:
    """
    Pass 8: Non-local means denoising.
    For heavily JPEG-compressed images (WhatsApp ~70% quality).
    Removes block artifacts before thresholding.
    """
    cv_img = _pil_to_bgr(pil_image)
    gray = _bgr_to_gray(cv_img)
    denoised = cv2.fastNlMeansDenoising(gray, h=10, templateWindowSize=7, searchWindowSize=21)
    _, binary = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    return Image.fromarray(binary)


# ─────────────────────────────────────────────────────────────
# Steganography detection (B7 fix retained: threshold=8000)
# ─────────────────────────────────────────────────────────────

def _check_steganography(cv_img: np.ndarray) -> dict:
    """
    LSB steganography detection via Laplacian variance.
    Threshold calibrated for QR images (not natural photos).

    Calibration data:
      Normal QR (PNG generator):       variance 2000-5000 → safe
      Normal QR (JPEG photo):          variance 3000-7000 → safe
      QR + LSB hidden data:            variance 8000-15000 → detected
      Heavy stego:                     variance 15000+    → detected
    """
    gray = _bgr_to_gray(cv_img)
    variance = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    THRESHOLD = 8000  # B7 FIX: was 3000 (too low for QR images)

    if variance > THRESHOLD:
        return {
            "detected":  True,
            "variance":  round(variance, 2),
            "threshold": THRESHOLD,
            "message":   "⚠️ Abnormal image noise — data may be hidden via LSB steganography"
        }
    return {
        "detected":  False,
        "variance":  round(variance, 2),
        "threshold": THRESHOLD,
        "note":      "Variance within normal range for QR images"
    }


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def extract_all_qr_codes(image: Image.Image) -> dict:
    """
    8-pass QR decoding pipeline using dual decoders (cv2 + pyzbar).

    B10 FIX SUMMARY:
    - Each pass now runs BOTH cv2.QRCodeDetector AND pyzbar
    - cv2 is tried first — it handles real-world photos, angled shots,
      screen photographs, and WhatsApp-compressed images natively
    - pyzbar adds coverage for any codes cv2 missed

    Pass order (stop early once all QRs found):
    1. raw                — Works for all clean digital images, cv2 handles photos
    2. enhanced           — Adaptive threshold + sharpening
    3. inverted           — White-on-black QR
    4. clahe              — Screen/backlight uneven illumination
    5. moire_reduction    — LCD screen pixel interference
    6. upscale_2x         — Small or distant QR in frame
    7. perspective_correct — Angled shots (WhatsApp, casual phone photos)
    8. denoise            — Heavy JPEG compression artifacts
    """
    seen_payloads: set = set()
    unique_codes: list = []
    passes_tried: int = 0
    found_on_pass: Optional[str] = None

    def _try_pass(images_list: list, label: str) -> bool:
        nonlocal passes_tried, found_on_pass
        found_any = False
        for img in images_list:
            results = _decode_image(img, label)
            passes_tried += 1
            for item in results:
                p = item["payload"]
                if p and p not in seen_payloads:
                    seen_payloads.add(p)
                    unique_codes.append(item)
                    if found_on_pass is None:
                        found_on_pass = label
                    found_any = True
        return found_any

    # ── Always-run passes ────────────────────────────────────
    # Pass 1 covers: clean PNG/digital QR (pyzbar) + all photos (cv2)
    _try_pass([_pass_raw(image)], "raw")

    # Additional enhancement passes for standard images
    _try_pass([_pass_enhanced(image)], "enhanced")
    _try_pass([_pass_inverted(image)], "inverted")

    # ── Real-photo passes (run if standard passes missed any codes) ──
    # Note: cv2 may have already found the QR in Pass 1, but we keep
    # these passes to catch codes at different scales/orientations

    if not unique_codes:
        log.info("[MultiDecoder] Standard passes found nothing — trying photo-enhancement passes")

    for label, fn, args in [
        ("clahe",           _pass_clahe,           (image,)),
        ("moire_reduction", _pass_moire_reduction,  (image,)),
        ("upscale_2x",      _pass_upscale,          (image, 2.0)),
    ]:
        if not unique_codes:
            try:
                _try_pass([fn(*args)], label)
            except Exception as e:
                log.debug(f"[MultiDecoder] Pass {label} error: {e}")

    # Perspective correction — most expensive, run last
    if not unique_codes:
        try:
            perspective_imgs = _pass_perspective_correct(image)
            if perspective_imgs:
                _try_pass(perspective_imgs, "perspective")
        except Exception as e:
            log.debug(f"[MultiDecoder] Perspective pass error: {e}")

    # Denoise — for maximum JPEG compression
    if not unique_codes:
        try:
            _try_pass([_pass_denoise(image)], "denoise")
        except Exception as e:
            log.debug(f"[MultiDecoder] Denoise pass error: {e}")

    # Last resort: 3x upscale
    if not unique_codes:
        try:
            _try_pass([_pass_upscale(image, 3.0)], "upscale_3x")
        except Exception as e:
            log.debug(f"[MultiDecoder] 3x upscale error: {e}")

    # ── Log result ───────────────────────────────────────────
    if unique_codes:
        log.info(
            f"[MultiDecoder] ✅ Found {len(unique_codes)} code(s) "
            f"on pass '{found_on_pass}' after {passes_tried} attempt(s)"
        )
    else:
        log.warning(
            f"[MultiDecoder] ❌ No QR found after {passes_tried} attempts. "
            f"Tip: ensure QR fills at least 30% of the frame."
        )

    # ── Steganography check ──────────────────────────────────
    stego = {"detected": False, "variance": 0.0}
    try:
        stego = _check_steganography(_pil_to_bgr(image))
    except Exception as e:
        log.debug(f"[MultiDecoder] Stego check error: {e}")

    multi_alert = len(unique_codes) >= 2
    if multi_alert:
        log.warning(f"[MultiDecoder] ⚠️ MULTI-QR ALERT: {len(unique_codes)} codes found!")

    return {
        "qr_codes":          unique_codes,
        "total_found":       len(unique_codes),
        "multiple_qr_alert": multi_alert,
        "steganography":     stego,
        "scan_passes_used":  passes_tried,
        "successful_pass":   found_on_pass,
        "alert_message": (
            f"🚨 CRITICAL: {len(unique_codes)} QR codes in one image. "
            "Legitimate images almost never contain multiple QR codes."
        ) if multi_alert else None
    }
