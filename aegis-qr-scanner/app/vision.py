"""
vision.py — Updated for Phase 1
Now uses multi_decoder.extract_all_qr_codes() instead of single-QR decode.
"""
import numpy as np
from PIL import Image
from app.logger import log
from app.multi_decoder import extract_all_qr_codes

def extract_qr_content(image: Image.Image):
    """
    LEGACY COMPATIBILITY WRAPPER — used by existing code that expects (text, is_stego).
    For full multi-QR scanning, call extract_all_qr_codes() directly from main.py.
    Returns: (first_payload_text_or_None, is_stego_bool)
    """
    result = extract_all_qr_codes(image)
    codes = result.get("qr_codes", [])
    is_stego = result.get("steganography", {}).get("detected", False)

    if codes:
        return codes[0]["payload"], is_stego
    return None, is_stego
