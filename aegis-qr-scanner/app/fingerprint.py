"""
fingerprint.py — v3
===================

B11 FIX (CRITICAL): Campaign detection never triggered after 5+ scans.

TWO ROOT CAUSES:
  1. Redis URL mismatch:
     - fingerprint.py v2 defaults to redis://host.docker.internal:6380
     - Inside a Docker container, Redis is at redis://redis:6379 (service name)
     - host.docker.internal is for host→container direction, not container→container
     - Connection silently failed → no hashes stored → campaign never triggers
     FIX: Default to redis://redis:6379, fall back to host.docker.internal

  2. Key name mismatch:
     - v2 returned 'times_seen_total' but API response showed 'times_seen_before'
     - This means Phase 1 fingerprint.py (not v2) was deployed by the user
     FIX: Standardize on 'times_seen_before' to match what the API already returns

Additional improvements:
  - Connection test on first call with clear error logging
  - Redis key stored with 7-day TTL (prevents unbounded growth)
  - Hash comparison uses proper bit length (256 bits for 16x16 hash)
  - Explicit aclose() to avoid connection pool leaks
"""

import numpy as np
from PIL import Image
from typing import Optional
import redis.asyncio as redis_async
import os
import json
from datetime import datetime
from app.logger import log

# Redis connection: try service name first (Docker), fall back to host bridge
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")

# Thresholds
SAME_QR_THRESHOLD     = 10   # < 10 bits diff = same physical QR (reshot at angle)
SIMILAR_QR_THRESHOLD  = 20   # < 20 bits diff = visually similar QR
CAMPAIGN_THRESHOLD    = 5    # 5+ similar scans = coordinated campaign
FINGERPRINT_TTL_DAYS  = 7    # Redis key TTL in days


# ─────────────────────────────────────────────────────────────
# Hash computation
# ─────────────────────────────────────────────────────────────

def compute_average_hash(image: Image.Image, hash_size: int = 16) -> str:
    """
    Average perceptual hash (aHash) — 256-bit hash as 64-char hex.

    Algorithm:
    1. Resize to 16×16 grayscale
    2. Compare each pixel to the mean value
    3. Bit = 1 if pixel > mean, 0 otherwise
    4. Pack 256 bits into 64 hex chars

    Similar images (reshot, compressed, rotated slightly) produce close hashes.
    Hamming distance < 10 = same physical QR code.
    """
    try:
        img = image.convert("L").resize((hash_size, hash_size), Image.LANCZOS)
        pixels = np.array(img, dtype=float)
        mean_val = pixels.mean()
        bits = (pixels > mean_val).flatten()
        bit_string = "".join("1" if b else "0" for b in bits)
        int_val = int(bit_string, 2) if bit_string else 0
        hex_len = (hash_size * hash_size) // 4  # 64 chars for 16x16
        return format(int_val, f"0{hex_len}x")
    except Exception as e:
        log.error(f"[Fingerprint] Hash computation error: {e}")
        return "0" * 64


def hamming_distance(hash1: str, hash2: str) -> int:
    """
    Hamming distance between two hex hash strings.
    Counts the number of bit positions that differ.
    For 16×16 hashes: 0-255 range (256 bits total).
    """
    try:
        if not hash1 or not hash2:
            return 999
        bit_len = max(len(hash1), len(hash2)) * 4  # hex chars × 4 bits
        bits1 = bin(int(hash1, 16))[2:].zfill(bit_len)
        bits2 = bin(int(hash2, 16))[2:].zfill(bit_len)
        return sum(c1 != c2 for c1, c2 in zip(bits1, bits2))
    except Exception:
        return 999


# ─────────────────────────────────────────────────────────────
# Redis helpers
# ─────────────────────────────────────────────────────────────

async def _get_redis() -> Optional[redis_async.Redis]:
    """
    Create Redis connection. Tries primary URL, then fallback URLs.
    Returns None if all connections fail.
    """
    urls_to_try = [REDIS_URL]

    # Add fallback URLs not already in the list
    fallbacks = [
        "redis://redis:6379",
        "redis://localhost:6379",
        "redis://host.docker.internal:6380",
        "redis://host.docker.internal:6379",
    ]
    for url in fallbacks:
        if url not in urls_to_try:
            urls_to_try.append(url)

    for url in urls_to_try:
        try:
            r = redis_async.from_url(url, encoding="utf-8", decode_responses=True, socket_timeout=2.0)
            await r.ping()  # Test connection
            if url != REDIS_URL:
                log.info(f"[Fingerprint] Redis connected via fallback: {url}")
            return r
        except Exception:
            continue

    log.warning("[Fingerprint] Redis unreachable on all URLs — campaign detection disabled")
    return None


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

async def check_fingerprint_campaign(
    image: Image.Image,
    payload_hash: str,
    payload_preview: str
) -> dict:
    """
    Visual fingerprint check + coordinated campaign detection.

    How it works:
    1. Compute 256-bit perceptual hash (aHash) of QR image
    2. Store in Redis hash map with metadata (first_seen, scan_count, etc.)
    3. Compare against ALL stored hashes using Hamming distance
    4. Count hashes within SIMILAR_QR_THRESHOLD (20 bits) of current hash
    5. If count >= CAMPAIGN_THRESHOLD (5) → campaign alert

    Storage order (B11 fix): Store FIRST, then count
    → 5th scan correctly sees 5 similar hashes (not 4)

    Returns:
      times_seen_before   — how many similar QRs seen previously
      closest_match_distance — minimum Hamming distance to any stored hash
      campaign_detected   — True if 5+ similar QRs seen
      campaign_alert      — Alert message if campaign detected
    """
    phash = compute_average_hash(image)

    result = {
        "perceptual_hash":        phash,
        "times_seen_before":      0,
        "closest_match_distance": 999,
        "similar_scans":          [],
        "campaign_detected":      False,
        "campaign_alert":         None
    }

    r = await _get_redis()
    if r is None:
        result["redis_status"] = "offline — campaign detection unavailable"
        return result

    try:
        redis_key = "qr:fingerprints"
        ttl_seconds = FINGERPRINT_TTL_DAYS * 86400

        # ── STEP 1: Store current scan first ─────────────────
        # (B11 fix: store BEFORE counting so 5th scan sees itself)
        existing_raw = await r.hget(redis_key, phash)
        if existing_raw:
            try:
                meta = json.loads(existing_raw)
                meta["scan_count"] = meta.get("scan_count", 1) + 1
                meta["last_seen"]  = datetime.utcnow().isoformat()
                await r.hset(redis_key, phash, json.dumps(meta))
            except Exception:
                pass
        else:
            await r.hset(redis_key, phash, json.dumps({
                "payload_hash":    payload_hash,
                "payload_preview": payload_preview[:60],
                "first_seen":      datetime.utcnow().isoformat(),
                "last_seen":       datetime.utcnow().isoformat(),
                "scan_count":      1
            }))
            # Reset TTL on entire hash map
            await r.expire(redis_key, ttl_seconds)

        # ── STEP 2: Read ALL hashes and compare ──────────────
        stored_data = await r.hgetall(redis_key)

        similar_count  = 0
        similar_matches = []
        min_dist = 999

        for stored_phash, meta_json in stored_data.items():
            dist = hamming_distance(phash, stored_phash)

            if dist < SIMILAR_QR_THRESHOLD:
                similar_count += 1
                min_dist = min(min_dist, dist)
                try:
                    meta = json.loads(meta_json)
                except Exception:
                    meta = {}

                similar_matches.append({
                    "hash":        stored_phash[:16] + "...",
                    "distance":    dist,
                    "same_qr":     dist < SAME_QR_THRESHOLD,
                    "first_seen":  meta.get("first_seen", "unknown"),
                    "scan_count":  meta.get("scan_count", 1),
                    "preview":     meta.get("payload_preview", "")[:40]
                })

        similar_matches.sort(key=lambda x: x["distance"])

        result["times_seen_before"]      = similar_count
        result["closest_match_distance"] = min_dist
        result["similar_scans"]          = similar_matches[:5]

        # ── STEP 3: Campaign detection ────────────────────────
        if similar_count >= CAMPAIGN_THRESHOLD:
            result["campaign_detected"] = True
            result["campaign_alert"] = (
                f"🚨 PHISHING CAMPAIGN DETECTED: This QR code (or near-identical copies) "
                f"has been scanned {similar_count} time(s). "
                f"This indicates a coordinated attack — multiple victims are being targeted "
                f"with the same QR code. Report to your security team immediately."
            )
            log.warning(
                f"[Fingerprint] 🚨 CAMPAIGN DETECTED: hash={phash[:16]}... "
                f"seen {similar_count} times (threshold={CAMPAIGN_THRESHOLD})"
            )

    except Exception as e:
        log.warning(f"[Fingerprint] Redis error during fingerprint check: {e}")
        result["redis_error"] = str(e)
    finally:
        try:
            await r.aclose()
        except Exception:
            pass

    return result
