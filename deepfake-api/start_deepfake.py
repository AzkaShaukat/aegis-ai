
#!/usr/bin/env python3
"""
Aegis AI Deepfake Detection API – Production Starter (no Docker)

Runs the API using Uvicorn with optimal settings:
- 4 worker processes (handles concurrent video scans)
- 600s keep‑alive timeout (for large video uploads)
- Port 8004 (configurable via .env or --port)
- Auto‑reload disabled in production (set DEV_MODE=1 to enable)

Usage:
    python start_deepfake.py
    python start_deepfake.py --port 8005 --workers 2
"""
import os
import sys
import argparse
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Load .env file if present (before any app imports)
try:
    from dotenv import load_dotenv
    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        load_dotenv(env_file)
        print(f"✅ Loaded environment from {env_file}")
except ImportError:
    print("⚠️  python-dotenv not installed. Using system env only.")

# Ensure critical settings exist
os.environ.setdefault("PORT", "8004")
os.environ.setdefault("LOG_LEVEL", "INFO")
os.environ.setdefault("MAX_VIDEO_SIZE_MB", "99999")

def check_redis():
    """Test Redis connectivity – warn but don't fail."""
    try:
        from app.utils.redis_client import get_redis
        r = get_redis()
        if r and r.ping():
            print("✅ Redis connected – caching and async jobs enabled")
        else:
            print("⚠️  Redis unavailable – running without caching (in-memory fallback)")
    except Exception as e:
        print(f"⚠️  Redis error: {e} – continuing with memory-only mode")

def check_models():
    """Warn if model files are missing – API will run in stub mode."""
    from app.config import get_settings
    settings = get_settings()
    missing = []
    for path in [
        settings.IMAGE_EFFICIENTNET_PATH,
        settings.IMAGE_VIT_PATH,
        settings.IMAGE_FREQCNN_PATH,
        settings.VIDEO_SPATIAL_PATH,
        settings.VIDEO_TEMPORAL_PATH,
        settings.VIDEO_FREQ_SRM_PATH,
    ]:
        if not os.path.exists(path):
            missing.append(path)
    if missing:
        print("⚠️  Missing model files (stub mode will be used):")
        for m in missing[:3]:
            print(f"     - {m}")
        if len(missing) > 3:
            print(f"     ... and {len(missing)-3} more")
    else:
        print("✅ All model files found")

def main():
    parser = argparse.ArgumentParser(description="Start Aegis Deepfake API")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", 8004)), help="Port (default: 8004)")
    parser.add_argument("--workers", type=int, default=int(os.getenv("WORKERS", 4)), help="Number of worker processes (default: 4)")
    parser.add_argument("--timeout-keep-alive", type=int, default=600, help="Keep-alive timeout in seconds (default: 600)")
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "info"), choices=["debug","info","warning","error"])
    parser.add_argument("--dev", action="store_true", help="Enable auto-reload (development mode, single worker)")
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  Aegis AI Deepfake Detection API – Starting")
    print("="*60)
    print(f"  Host: {args.host}:{args.port}")
    print(f"  Workers: {1 if args.dev else args.workers}")
    print(f"  Timeout keep-alive: {args.timeout_keep_alive}s")
    print(f"  Log level: {args.log_level.upper()}")
    print("-"*60)

    # Pre-flight checks
    check_redis()
    check_models()

    print("\n🚀 Launching Uvicorn...\n")

    # Build uvicorn command
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        workers=1 if args.dev else args.workers,
        log_level=args.log_level.lower(),   # ← force lowercase
        timeout_keep_alive=args.timeout_keep_alive,
        reload=args.dev,
        reload_dirs=["app"] if args.dev else None,
    )
if __name__ == "__main__":
    main()