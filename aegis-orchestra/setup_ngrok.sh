#!/usr/bin/env bash
# =============================================================
# setup_ngrok.sh — Start ngrok with your FIXED static URL
#
# Your static ngrok URL:
#   https://emma-subhyaline-incongrously.ngrok-free.dev
#
# Usage:  chmod +x setup_ngrok.sh && ./setup_ngrok.sh
# =============================================================

set -e

PORT=8006
PUBLIC_URL="https://emma-subhyaline-incongrously.ngrok-free.dev"
VERIFY_TOKEN="aegis_webhook_verify_2026"

echo ""
echo "🛡️  Aegis Orchestra — ngrok Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check ngrok installed
if ! command -v ngrok &> /dev/null; then
    echo "❌ ngrok not found."
    echo "Install: https://ngrok.com/download"
    echo "  Windows: winget install ngrok"
    echo "  Mac:     brew install ngrok"
    echo "  Linux:   sudo snap install ngrok"
    exit 1
fi

# Check orchestra running
echo "🔍 Checking orchestra on port $PORT..."
if curl -s --max-time 3 http://localhost:$PORT/health > /dev/null 2>&1; then
    echo "✅ Orchestra is running"
else
    echo "⚠️  Orchestra not responding. Start it first:"
    echo "   docker-compose -f docker-compose.dev.yml up --build -d"
    echo ""
    echo "Continuing (ngrok will still start)..."
fi

echo ""
echo "🚀 Starting ngrok with static domain..."
echo ""

# Start ngrok with the fixed static domain
ngrok http $PORT --domain=emma-subhyaline-incongrously.ngrok-free.dev &
NGROK_PID=$!
sleep 3

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ ngrok tunnel active!"
echo ""
echo "📋 Meta Webhook Configuration:"
echo "   Callback URL  : $PUBLIC_URL/webhook"
echo "   Verify Token  : $VERIFY_TOKEN"
echo "   Subscriptions : messages"
echo ""
echo "📝 Steps to configure on Meta:"
echo "   1. https://developers.facebook.com → Your App → WhatsApp → Configuration"
echo "   2. Webhook → Edit"
echo "   3. Callback URL: $PUBLIC_URL/webhook"
echo "   4. Verify Token: $VERIFY_TOKEN"
echo "   5. Click 'Verify and Save'"
echo "   6. Under Webhook Fields → Subscribe to: messages"
echo ""
echo "🔑 Required in your .env file:"
echo "   WHATSAPP_TOKEN=<your_System_User_access_token>"
echo "   WHATSAPP_PHONE_NUMBER_ID=<your_phone_number_id>"
echo "   PUBLIC_URL=$PUBLIC_URL"
echo ""
echo "📊 ngrok dashboard: http://localhost:4040"
echo "❤️  Health check:    $PUBLIC_URL/health"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Press Ctrl+C to stop ngrok"
wait $NGROK_PID
