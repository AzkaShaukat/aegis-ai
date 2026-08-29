# app/services_logic/ — Files to copy from your WhatsApp project

## Copy these AS-IS from your WhatsApp project (app/services/):

```
WhatsApp project:                           → Copy to here:
app/services/smishing_engine.py             → backend/app/services_logic/smishing_engine.py
app/services/profile_intelligence.py        → backend/app/services_logic/profile_intelligence.py
app/services/username_intelligence.py       → backend/app/services_logic/username_intelligence.py
app/services/long_term_memory.py            → backend/app/services_logic/long_term_memory.py
app/services/deepfake_service.py            → backend/app/services_logic/deepfake_service.py
app/services/threat_feed.py                 → backend/app/services_logic/threat_feed.py
```

## Import path fix needed in each file:

In every copied file, change:
    from app.config import get_settings
To:
    from app.core.config import get_settings

And change:
    from app.session import get_redis
To:
    (see long_term_memory.py note below)

## long_term_memory.py special fix:

The `get_redis()` import needs updating. Replace:
    from app.session import get_redis
With:
    async def _get_redis():
        import redis.asyncio as aioredis
        from app.core.config import get_settings
        s = get_settings()
        return await aioredis.from_url(s.redis_url, decode_responses=True)

Then replace all `get_redis()` calls in that file with `_get_redis()`.

## After copying, verify:
```bash
python -c "from app.services_logic.smishing_engine import analyse_smishing; print('OK')"
python -c "from app.services_logic.profile_intelligence import compute_unified_verdict; print('OK')"
```
