Document file mapping and issues
bash

# Aegis AI — WhatsApp ↔ Web File Mapping

| Role | WhatsApp File | Web Equivalent | Sync Status |
|------|--------------|----------------|-------------|
| Intent routing + service calls | `orchestrator.py` | `backend/app/services/web_orchestrator.py` | ⚠️ Needs fix (QR bug, no Ollama) |
| Response formatting | `responses.py` | `frontend/src/components/Chat/MessageBubble.tsx` | ⚠️ Different format by design |
| Session management | `session.py` | `backend/app/services/chat_service_ext.py` | ✅ Similar |
| Config / secrets | `config.py` | `backend/app/core/config.py` | ✅ Similar |
| Transport / entrypoint | `app.py` (webhook) | `backend/app/api/ws_handler.py` | ✅ Different transport, same logic |
| Human explanation (Ollama) | Inside `orchestrator.py` | ❌ MISSING in web_orchestrator.py | 🔴 Critical gap |
| Service health check | `orchestrator.py` retry | `backend/app/router/health_check.py` | ⚠️ Startup-only, not per-request |
| Frontend state | N/A | `frontend/src/stores/chatStore.ts` | Web-only |
| WebSocket hook | N/A | `frontend/src/hooks/useWebSocket.ts` | Web-only |

## Issues to fix:
1. Intent bug: "scan this link" detected as QR (regex too broad)
2. QR always returns offline even when port 8001 is UP
3. Ollama human explanation missing from every web reply
4. Structured card shows too many technical fields
5. Risk scoring: "Low Risk" string not matching SAFE/HIGH enum
6. Score ring showing 0%/Danger incorrectly
EOF
cat /home/claude/FILE_MAP.md
Output

# Aegis AI — WhatsApp ↔ Web File Mapping

| Role | WhatsApp File | Web Equivalent | Sync Status |
|------|--------------|----------------|-------------|
| Intent routing + service calls | `orchestrator.py` | `backend/app/services/web_orchestrator.py` | ⚠️ Needs fix (QR bug, no Ollama) |
| Response formatting | `responses.py` | `frontend/src/components/Chat/MessageBubble.tsx` | ⚠️ Different format by design |
| Session management | `session.py` | `backend/app/services/chat_service_ext.py` | ✅ Similar |
| Config / secrets | `config.py` | `backend/app/core/config.py` | ✅ Similar |
| Transport / entrypoint | `app.py` (webhook) | `backend/app/api/ws_handler.py` | ✅ Different transport, same logic |
| Human explanation (Ollama) | Inside `orchestrator.py` | ❌ MISSING in web_orchestrator.py | 🔴 Critical gap |
| Service health check | `orchestrator.py` retry | `backend/app/router/health_check.py` | ⚠️ Startup-only, not per-request |
| Frontend state | N/A | `frontend/src/stores/chatStore.ts` | Web-only |
| WebSocket hook | N/A | `frontend/src/hooks/useWebSocket.ts` | Web-only |

## Issues to fix:
1. Intent bug: "scan this link" detected as QR (regex too broad)
2. QR always returns offline even when port 8001 is UP
3. Ollama human explanation missing from every web reply
4. Structured card shows too many technical fields
5. Risk scoring: "Low Risk" string not matching SAFE/HIGH enum
6. Score ring showing 0%/Danger incorrectly
