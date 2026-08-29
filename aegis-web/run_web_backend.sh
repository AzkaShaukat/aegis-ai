#!/bin/bash
# run_web_backend.sh — Run Aegis Web backend on host (no Docker)
# Run from the aegis-web/ directory.
set -e

echo ""
echo "🛡️  Aegis AI — Web Backend"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check .env.web exists
if [ ! -f ".env.web" ]; then
    echo "❌ .env.web not found!"
    echo "   Copy .env.web.example → .env.web and fill in your values."
    exit 1
fi

cd backend

# Install dependencies
echo "[1/3] Installing Python dependencies..."
pip install -r requirements.txt --quiet
echo "      ✅ Done"

# Run Alembic migrations
echo "[2/3] Running database migrations..."
alembic upgrade head
echo "      ✅ Migrations applied"

# Start server
echo "[3/3] Starting web backend on port 8007..."
echo ""
echo "  API docs:  http://localhost:8007/docs"
echo "  Health:    http://localhost:8007/health"
echo "  WebSocket: ws://localhost:8007/ws/chat?token=<jwt>"
echo ""
echo "  Press Ctrl+C to stop"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8007 \
    --reload \
    --env-file ../.env.web \
    --log-level info
