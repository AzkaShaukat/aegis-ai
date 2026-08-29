#!/usr/bin/env python3
"""
Generate synthetic test assets for Aegis Deepfake API tests.
Run this script once before running the integration test suite.

Usage:
    python scripts/generate_synthetic_assets.py

Outputs:
    tests/assets/real_face_synth.jpg        — clear synthetic face (quality gate PASS)
    tests/assets/blurry_face_synth.jpg      — blurry face (blur warning)
    tests/assets/tiny_face_synth.jpg        — tiny face (resolution warning)
    tests/assets/no_face_synth.jpg          — no face (gate FAIL)
    tests/assets/multi_face_synth.jpg       — two faces (multi-face note)
    tests/assets/short_video_synth.mp4      — 5-second synthetic video
    tests/assets/compressed_video_synth.mp4 — simulated WhatsApp compression
"""
from pathlib import Path
import cv2
import numpy as np

ASSETS_DIR = Path(__file__).parent.parent / "tests" / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)


def draw_face(img, cx, cy, radius, with_details=True):
    """Draw a synthetic face on a BGR image."""
    # Head
    cv2.circle(img, (cx, cy), radius, (180, 140, 100), -1)
    # Hair
    cv2.ellipse(img, (cx, cy - radius // 2), (radius, radius // 2), 0, 180, 360, (60, 30, 10), -1)
    if with_details:
        # Eyes
        eye_y = cy - radius // 4
        cv2.circle(img, (cx - radius // 3, eye_y), radius // 10, (255, 255, 255), -1)
        cv2.circle(img, (cx + radius // 3, eye_y), radius // 10, (255, 255, 255), -1)
        cv2.circle(img, (cx - radius // 3, eye_y), radius // 18, (30, 20, 10), -1)
        cv2.circle(img, (cx + radius // 3, eye_y), radius // 18, (30, 20, 10), -1)
        # Nose
        pts = np.array([[cx, cy - radius//10], [cx - 8, cy + radius//8], [cx + 8, cy + radius//8]])
        cv2.polylines(img, [pts], True, (130, 90, 70), 2)
        # Mouth
        cv2.ellipse(img, (cx, cy + radius // 3), (radius // 3, radius // 8), 0, 0, 180, (80, 50, 40), 2)
        # Eyebrows
        cv2.line(img, (cx - radius//3 - 10, eye_y - 12), (cx - radius//3 + 10, eye_y - 10), (50, 30, 10), 3)
        cv2.line(img, (cx + radius//3 - 10, eye_y - 10), (cx + radius//3 + 10, eye_y - 12), (50, 30, 10), 3)


def generate_real_face():
    """Clear, sharp, well-sized face — quality gate PASS."""
    img = np.ones((400, 400, 3), dtype=np.uint8) * 220
    # Background gradient
    for y in range(400):
        img[y] = (int(200 + y * 0.05), int(210 + y * 0.03), int(220 - y * 0.04))
    draw_face(img, 200, 200, 100)
    path = ASSETS_DIR / "real_face_synth.jpg"
    cv2.imwrite(str(path), img, [cv2.IMWRITE_JPEG_QUALITY, 95])
    print(f"Created: {path}")


def generate_blurry_face():
    """Blurry face — should trigger blur warning."""
    img = np.ones((400, 400, 3), dtype=np.uint8) * 220
    draw_face(img, 200, 200, 100)
    # Heavy Gaussian blur
    img = cv2.GaussianBlur(img, (0, 0), sigmaX=12.0)
    path = ASSETS_DIR / "blurry_face_synth.jpg"
    cv2.imwrite(str(path), img, [cv2.IMWRITE_JPEG_QUALITY, 80])
    print(f"Created: {path}")


def generate_tiny_face():
    """Tiny face in a large image — should trigger resolution warning."""
    img = np.ones((600, 600, 3), dtype=np.uint8) * 180
    draw_face(img, 300, 300, 20)  # 20px radius = 40px face
    path = ASSETS_DIR / "tiny_face_synth.jpg"
    cv2.imwrite(str(path), img, [cv2.IMWRITE_JPEG_QUALITY, 90])
    print(f"Created: {path}")


def generate_no_face():
    """No face — quality gate should FAIL."""
    img = np.ones((300, 300, 3), dtype=np.uint8) * 150
    # Draw a car (definitely not a face)
    cv2.rectangle(img, (50, 150), (250, 220), (40, 40, 40), -1)   # body
    cv2.rectangle(img, (80, 100), (220, 160), (60, 60, 60), -1)   # roof
    cv2.circle(img, (100, 220), 25, (20, 20, 20), -1)              # wheel
    cv2.circle(img, (200, 220), 25, (20, 20, 20), -1)              # wheel
    path = ASSETS_DIR / "no_face_synth.jpg"
    cv2.imwrite(str(path), img, [cv2.IMWRITE_JPEG_QUALITY, 90])
    print(f"Created: {path}")


def generate_multi_face():
    """Two faces — should trigger multi-face note."""
    img = np.ones((300, 600, 3), dtype=np.uint8) * 210
    draw_face(img, 150, 150, 80)
    draw_face(img, 450, 150, 80)
    path = ASSETS_DIR / "multi_face_synth.jpg"
    cv2.imwrite(str(path), img, [cv2.IMWRITE_JPEG_QUALITY, 90])
    print(f"Created: {path}")


def generate_short_video():
    """5-second video at 15fps with a moving synthetic face."""
    path = ASSETS_DIR / "short_video_synth.mp4"
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    vw = cv2.VideoWriter(str(path), fourcc, 15.0, (320, 240))

    for i in range(75):  # 5 seconds × 15fps
        frame = np.ones((240, 320, 3), dtype=np.uint8) * 200
        # Slightly move the face each frame to test temporal model
        cx = 160 + int(10 * np.sin(i * 0.2))
        cy = 120 + int(5 * np.sin(i * 0.3))
        draw_face(frame, cx, cy, 60)
        vw.write(frame)

    vw.release()
    print(f"Created: {path}")


def generate_compressed_video():
    """Video simulating WhatsApp-style compression (lower quality)."""
    path = ASSETS_DIR / "compressed_video_synth.mp4"
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    vw = cv2.VideoWriter(str(path), fourcc, 10.0, (240, 180))

    for i in range(60):
        frame = np.ones((180, 240, 3), dtype=np.uint8) * 190
        draw_face(frame, 120, 90, 45)
        # Simulate compression noise
        noise = np.random.randint(-15, 15, frame.shape, dtype=np.int16)
        frame = np.clip(frame.astype(np.int16) + noise, 0, 255).astype(np.uint8)
        vw.write(frame)

    vw.release()
    print(f"Created: {path}")


if __name__ == "__main__":
    print(f"Generating synthetic test assets in: {ASSETS_DIR}")
    generate_real_face()
    generate_blurry_face()
    generate_tiny_face()
    generate_no_face()
    generate_multi_face()
    generate_short_video()
    generate_compressed_video()
    print("\nAll assets generated. Use them as:")
    print("  Real face:   tests/assets/real_face_synth.jpg")
    print("  Blurry face: tests/assets/blurry_face_synth.jpg")
    print("  No face:     tests/assets/no_face_synth.jpg")
    print("  Short video: tests/assets/short_video_synth.mp4")
    print("\nFor real deepfake test data, see tests/assets/README.md")
