"""
exif_analyzer.py — Phase 2, Feature 2.2
EXIF & Image Metadata Extractor

Extracts and analyses metadata from QR code images.
Reveals: GPS coordinates, camera/device info, editing software,
         creation timestamp, and security-relevant flags.
"""

from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from typing import Optional
from app.logger import log
import re


def _dms_to_decimal(dms_tuple, ref: str) -> Optional[float]:
    """Converts Degrees/Minutes/Seconds tuple to decimal degrees."""
    try:
        d = float(dms_tuple[0])
        m = float(dms_tuple[1])
        s = float(dms_tuple[2])
        decimal = d + m / 60.0 + s / 3600.0
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


def _extract_gps(exif_raw: dict) -> Optional[dict]:
    """Extracts and converts GPS data from raw EXIF."""
    GPS_TAG_ID = 34853
    gps_ifd = exif_raw.get(GPS_TAG_ID)
    if not gps_ifd:
        return None

    gps = {}
    for tag_id, value in gps_ifd.items():
        tag_name = GPSTAGS.get(tag_id, str(tag_id))
        gps[tag_name] = value

    lat = _dms_to_decimal(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef", "N"))
    lon = _dms_to_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef", "E"))

    if lat is None or lon is None:
        return None

    alt = None
    if "GPSAltitude" in gps:
        try:
            alt = float(gps["GPSAltitude"])
            if gps.get("GPSAltitudeRef") == 1:
                alt = -alt
        except Exception:
            pass

    return {
        "latitude":     lat,
        "longitude":    lon,
        "altitude_m":   alt,
        "google_maps":  f"https://maps.google.com/?q={lat},{lon}",
        "apple_maps":   f"https://maps.apple.com/?q={lat},{lon}",
        "raw_ref": {
            "lat_ref": gps.get("GPSLatitudeRef"),
            "lon_ref": gps.get("GPSLongitudeRef")
        }
    }


# Software that indicates image editing (security relevant)
EDITING_SOFTWARE = [
    "photoshop", "gimp", "paint.net", "affinity", "lightroom",
    "pixelmator", "snapseed", "vsco", "instagram", "snapchat",
    "editor", "edit", "retouch", "filter", "enhance",
]

# Known QR code generation tools (low risk)
QR_GENERATOR_SOFTWARE = [
    "qr", "barcode", "zxing", "zbar", "python", "qrcode",
    "phpqrcode", "google", "me-qr", "qr-code"
]


def analyze_exif(image: Image.Image) -> dict:
    """
    Extracts EXIF metadata from a QR code image and returns security analysis.

    Returns:
    {
        "available": bool,
        "device": {...},
        "timestamp": str,
        "software": str,
        "gps": {...} or None,
        "flags": [str],
        "risk_score": int,
        "security_notes": [str]
    }
    """
    try:
        exif_raw = image._getexif()
    except (AttributeError, Exception):
        exif_raw = None

    if not exif_raw:
        return {
            "available": False,
            "note": "No EXIF metadata in this image (common for PNG or generated QR codes)"
        }

    # Parse all tags
    exif = {}
    for tag_id, value in exif_raw.items():
        tag_name = TAGS.get(tag_id, f"tag_{tag_id}")
        try:
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            exif[tag_name] = str(value)[:300]
        except Exception:
            exif[tag_name] = repr(value)[:200]

    # Extract key fields
    make = exif.get("Make", "").strip()
    model = exif.get("Model", "").strip()
    software = exif.get("Software", "").strip()
    datetime_orig = exif.get("DateTimeOriginal", exif.get("DateTime", ""))
    orientation = exif.get("Orientation", "")
    image_width = exif.get("ExifImageWidth", exif.get("ImageWidth", ""))
    image_height = exif.get("ExifImageHeight", exif.get("ImageLength", ""))

    # GPS
    gps_data = _extract_gps(exif_raw)

    # ── Security Analysis ────────────────────────────────────
    flags = []
    security_notes = []
    risk_score = 0

    # 1. GPS embedded
    if gps_data:
        flags.append(f"GPS COORDINATES: {gps_data['latitude']}, {gps_data['longitude']}")
        security_notes.append(
            f"Image contains GPS coordinates — QR was photographed at lat={gps_data['latitude']}, "
            f"lon={gps_data['longitude']}. This reveals physical location."
        )
        risk_score += 10

    # 2. Editing software detected
    software_lower = software.lower()
    is_edited = any(s in software_lower for s in EDITING_SOFTWARE)
    is_qr_tool = any(s in software_lower for s in QR_GENERATOR_SOFTWARE)

    if is_edited and not is_qr_tool:
        flags.append(f"IMAGE EDITED: '{software}' — QR may have been manipulated post-creation")
        security_notes.append(
            f"Image was processed with '{software}'. "
            "Edited QR images may have had content modified or overlays added."
        )
        risk_score += 30

    # 3. Camera/device info
    if make or model:
        device_str = f"{make} {model}".strip()
        flags.append(f"DEVICE: {device_str}")
        security_notes.append(f"QR was photographed with: {device_str}")

    # 4. No make/model but has other EXIF = possible EXIF stripping attempt
    if not make and not model and len(exif) > 5:
        flags.append("DEVICE STRIPPED: Camera info removed from EXIF")
        security_notes.append("Camera make/model was stripped — may indicate attempt to hide identity")
        risk_score += 15

    # 5. Timestamp analysis
    if datetime_orig:
        # Check if timestamp is suspiciously old or in the future
        import re as re_mod
        year_match = re_mod.search(r'(\d{4})', datetime_orig)
        if year_match:
            year = int(year_match.group(1))
            if year < 2010:
                flags.append(f"OLD TIMESTAMP: {datetime_orig} — may be falsified")
                security_notes.append(f"Image timestamp ({datetime_orig}) is unusually old")
                risk_score += 10
            elif year > 2030:
                flags.append(f"FUTURE TIMESTAMP: {datetime_orig} — likely falsified")
                security_notes.append(f"Image timestamp ({datetime_orig}) is in the future — EXIF may be manipulated")
                risk_score += 20

    # 6. Orientation != 1 = image was rotated (camera held at angle)
    if orientation and orientation != "1" and orientation != "Horizontal (normal)":
        security_notes.append(
            f"Image orientation: {orientation} — QR code was photographed at an angle"
        )

    return {
        "available":       True,
        "device": {
            "make":        make or None,
            "model":       model or None,
            "software":    software or None,
            "is_edited":   is_edited and not is_qr_tool,
            "is_qr_tool":  is_qr_tool
        },
        "timestamp":       datetime_orig or None,
        "dimensions": {
            "width":  image_width,
            "height": image_height
        },
        "orientation":     orientation or None,
        "gps":             gps_data,
        "flags":           flags,
        "security_notes":  security_notes,
        "risk_score":      min(risk_score, 60),
        "exif_field_count": len(exif),
        "raw_fields": {
            k: v for k, v in exif.items()
            if k in ["Make", "Model", "Software", "DateTimeOriginal",
                     "DateTime", "Orientation", "ExifImageWidth", "ExifImageHeight",
                     "Flash", "FocalLength", "ISOSpeedRatings"]
        }
    }
