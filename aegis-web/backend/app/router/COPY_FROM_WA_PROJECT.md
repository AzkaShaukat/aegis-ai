# app/router/ — Files to copy from your WhatsApp project

## Already included (no changes needed):
- dispatcher.py     ✅ included — adapted for web config
- health_check.py   ✅ included — zero changes

## Copy these AS-IS from your WhatsApp project:

```
WhatsApp project:                    → Copy to here:
app/router/extractor.py              → backend/app/router/extractor.py
app/router/intent.py                 → backend/app/router/intent.py
app/router/ollama_client.py          → backend/app/router/ollama_client.py
app/router/gemini_client.py          → backend/app/router/gemini_client.py
```

The only file that needs a 2-line edit is ollama_client.py:
Change the import at the top from:
    from app.config import get_settings
To:
    from app.core.config import get_settings

## After copying, verify:
```bash
cd backend
python -c "from app.router.extractor import extract; print('OK')"
python -c "from app.router.intent import classify; print('OK')"
python -c "from app.router.ollama_client import is_ollama_available; print('OK')"
```
