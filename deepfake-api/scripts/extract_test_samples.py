#!/usr/bin/env python3
"""
Extract individual face images and video frames from your HDF5 training files.
Creates ready-to-use test assets without needing external dataset downloads.

Usage:
    python scripts/extract_test_samples.py --count 20
    python scripts/extract_test_samples.py --hdf5 path/to/test.h5 --count 10
"""
import argparse
import os
import sys
from pathlib import Path

import cv2
import numpy as np

ASSETS_DIR = Path(__file__).parent.parent / "tests" / "assets"


def extract_from_hdf5_image(h5_path: str, output_dir: Path, count: int, label: str):
    """
    Extract `count` face images from an HDF5 file (Doc 1 format).
    Expected HDF5 structure: datasets 'images' (N, H, W, 3) and 'labels' (N,)
    """
    try:
        import h5py
    except ImportError:
        print("h5py not installed. pip install h5py")
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with h5py.File(h5_path, "r") as f:
            print(f"HDF5 keys: {list(f.keys())}")

            images_key = next(
                (k for k in ["images", "data", "x"] if k in f), None
            )
            labels_key = next(
                (k for k in ["labels", "y", "targets"] if k in f), None
            )

            if images_key is None:
                print(f"Could not find images dataset in {h5_path}")
                return

            images = f[images_key]
            labels = f[labels_key] if labels_key else None

            total = images.shape[0]
            saved = 0

            for i in range(min(total, count * 10)):
                img = images[i]
                lbl = int(labels[i]) if labels is not None else -1

                if label == "fake" and lbl != 1:
                    continue
                if label == "real" and lbl != 0:
                    continue

                # Convert to BGR for OpenCV
                if img.dtype != np.uint8:
                    img = (img * 255).clip(0, 255).astype(np.uint8)
                img_bgr = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)

                fname = output_dir / f"{label}_{saved:04d}.jpg"
                cv2.imwrite(str(fname), img_bgr, [cv2.IMWRITE_JPEG_QUALITY, 95])
                saved += 1

                if saved >= count:
                    break

            print(f"Extracted {saved} {label} images to {output_dir}")

    except Exception as e:
        print(f"Error reading {h5_path}: {e}")


def extract_from_hdf5_temporal(h5_path: str, output_dir: Path, count: int, label: str):
    """
    Extract video frame sequences from a temporal HDF5 file (Doc 2 format).
    Saves the middle frame of each sequence as a JPEG.
    """
    try:
        import h5py
    except ImportError:
        print("h5py not installed.")
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with h5py.File(h5_path, "r") as f:
            print(f"Temporal HDF5 keys: {list(f.keys())}")

            seq_key = next(
                (k for k in ["sequences", "frames", "data", "x"] if k in f), None
            )
            labels_key = next(
                (k for k in ["labels", "y"] if k in f), None
            )

            if seq_key is None:
                print(f"Could not find sequences dataset in {h5_path}")
                return

            seqs = f[seq_key]   # expected: (N, T, H, W, 3) or (N, T, 3, H, W)
            labels = f[labels_key] if labels_key else None

            saved = 0
            total = seqs.shape[0]

            for i in range(min(total, count * 10)):
                lbl = int(labels[i]) if labels is not None else -1
                if label == "fake" and lbl != 1:
                    continue
                if label == "real" and lbl != 0:
                    continue

                seq = seqs[i]  # (T, H, W, 3) or (T, 3, H, W)
                T = seq.shape[0]
                mid_frame = seq[T // 2]

                if mid_frame.shape[0] == 3:  # (3, H, W) → (H, W, 3)
                    mid_frame = mid_frame.transpose(1, 2, 0)

                if mid_frame.dtype != np.uint8:
                    mid_frame = (mid_frame * 255).clip(0, 255).astype(np.uint8)

                img_bgr = cv2.cvtColor(mid_frame, cv2.COLOR_RGB2BGR)
                fname = output_dir / f"{label}_frame_{saved:04d}.jpg"
                cv2.imwrite(str(fname), img_bgr)
                saved += 1

                if saved >= count:
                    break

            print(f"Extracted {saved} {label} frame images from temporal HDF5")

    except Exception as e:
        print(f"Error reading {h5_path}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Extract test samples from HDF5 files")
    parser.add_argument("--count", type=int, default=20,
                        help="Number of samples to extract per class")
    parser.add_argument("--hdf5", type=str, default=None,
                        help="Path to HDF5 file. If not given, looks for test.h5 in common locations.")
    parser.add_argument("--temporal", action="store_true",
                        help="Extract from temporal (video sequence) HDF5")
    parser.add_argument("--label", choices=["fake", "real", "both"], default="both",
                        help="Which class to extract")
    args = parser.parse_args()

    # Try to find HDF5 automatically
    if args.hdf5 is None:
        candidates = [
            "models/hdf5/test.h5",
            "../hdf5/test.h5",
            "test.h5",
        ]
        for c in candidates:
            if os.path.exists(c):
                args.hdf5 = c
                print(f"Found HDF5: {c}")
                break

    if args.hdf5 is None:
        print("No HDF5 file found. Specify with --hdf5 path/to/test.h5")
        print("Falling back to synthetic asset generation...")
        os.system(f"{sys.executable} scripts/generate_synthetic_assets.py")
        return

    labels = ["fake", "real"] if args.label == "both" else [args.label]

    for lbl in labels:
        out_dir = ASSETS_DIR / f"{lbl}_faces"
        if args.temporal:
            extract_from_hdf5_temporal(args.hdf5, out_dir, args.count, lbl)
        else:
            extract_from_hdf5_image(args.hdf5, out_dir, args.count, lbl)

    print("\nDone. Run integration tests with:")
    print("  pytest tests/ -m integration")


if __name__ == "__main__":
    main()
