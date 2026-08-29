# Aegis QR Scanner — Test Suite

Complete test coverage for all Phase 1–4 features.

## Setup

```bash
# 1. Start Aegis
cd aegis-qr-scanner
docker-compose up --build

# 2. Install test dependencies
pip install pytest pytest-asyncio httpx websockets qrcode[pil] numpy

# 3. Run all tests
cd aegis-tests
AEGIS_BASE_URL=http://localhost:8001 pytest -v
```

## Test Files

| File | Coverage |
|---|---|
| `test_phase1.py` | Multi-QR, types, deobfuscation, smishing, blacklist, WiFi, crypto, caching |
| `test_phase2.py` | Tamper detection, EXIF, visual fingerprinting, steganography |
| `test_phase3.py` | GSB, AbuseIPDB, EmailRep, NumVerify, Chainabuse, Blockchain.com |
| `test_phase4.py` | Async scan, history, batch, WebSocket, QR generator |
| `test_ml_model.py` | ML prediction quality, sanity checks, overfitting detection |

## Run Subsets

```bash
# Phase 4 only
pytest tests/test_phase4.py -v

# Async tests only
pytest -v -k "async"

# Skip slow tests
pytest -v -m "not slow"

# Stop on first failure
pytest -v -x

# Show print output (useful for ML diagnostic tests)
pytest -v -s tests/test_ml_model.py
```

## Notes

- WebSocket tests require `pip install websockets`
- Round-trip QR test requires `pip install pyzbar`
- If `qrcode[pil]` not installed, tests are auto-skipped
- Set `AEGIS_BASE_URL` if running on a different port
