# Aegis AI v4 — Complete Setup Guide

---

## Step 1: Copy files

Delete your old `social_media_analyzer` folder entirely.
Copy the contents of this download into a new `social_media_analyzer` folder.

```
social_media_analyzer/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── pytest.ini
├── manual_test.py
├── TEST_INPUTS.md
├── SETUP_GUIDE.md
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── models.py
│   ├── cache.py
│   ├── main.py
│   ├── scraper/
│   │   ├── __init__.py
│   │   ├── base.py        ← URL builder
│   │   ├── twitter.py
│   │   ├── instagram.py
│   │   ├── tiktok.py
│   │   └── router.py      ← ALL scrapers + router in one import
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── f01–f06        ← Phase 1 (no keys)
│   │   ├── f07–f12        ← Phase 2 (optional keys)
│   │   ├── f13–f16        ← Phase 3 (mostly no keys)
│   │   ├── f17–f19        ← Phase 4 (optional keys)
│   │   ├── email_analyzer.py
│   │   └── phone_analyzer.py
│   └── scoring/
│       ├── __init__.py
│       └── engine.py
└── tests/
    ├── __init__.py
    └── test_automated.py
```

---

## Step 2: Create .env file

```powershell
cd D:\Aegis AI\social_media_analyzer
copy .env.example .env
```

The app works with zero keys. Add keys one by one as you get them.

---

## Step 3: Start Docker

```powershell
docker compose up --build
```

You should see:
```
aegis-analyzer  | Aegis AI v4 — Profile & Credential Analyzer
aegis-analyzer  | Redis: OK
aegis-analyzer  | INFO:  Uvicorn running on http://0.0.0.0:8003
```

Open: http://localhost:8003/docs

---

## Step 4: Run tests

### Unit tests (offline — no Docker needed):
```powershell
pip install pytest pytest-asyncio pydantic-settings phonenumbers dnspython python-Levenshtein
pytest tests/ -v
```
Expected: 40+ tests, all PASS.

### Live API tests (Docker must be running):
```powershell
pip install requests
python manual_test.py
```

---

## Step 5: Try these test inputs

Go to http://localhost:8003/docs → click POST /analyze → Try it out

### Email tests (paste into request body):
```json
{"value":"test@gmail.com","input_type":"email"}
{"value":"random@mailinator.com","input_type":"email"}
{"value":"notanemail","input_type":"email"}
```

### Phone tests:
```json
{"value":"+923001234567","input_type":"phone"}
{"value":"+923001234567","input_type":"whatsapp"}
{"value":"+1234","input_type":"phone"}
```

### Social media (scrapes live):
```json
{"value":"elonmusk","input_type":"social_media","platform":"twitter"}
{"value":"cristiano","input_type":"social_media","platform":"instagram"}
{"value":"khaby.lame","input_type":"social_media","platform":"tiktok"}
```

---

## Getting Optional API Keys

### Twitter Bearer Token (F-07 heuristics) — FREE
1. developer.twitter.com → Sign up (free)
2. Create Project → Create App
3. Keys and Tokens → Bearer Token → Copy
4. Add to `.env`: `TWITTER_BEARER_TOKEN=your_token`

> Replaces BotSentinel which is down until May 2026.

### Social Blade (F-08) — FREE
1. socialblade.com/api → Register
2. Dashboard → API Access → copy Client ID + Token
3. Add to `.env`: `SOCIALBLADE_CLIENT_ID=...` and `SOCIALBLADE_TOKEN=...`

### Botometer via RapidAPI (F-09) — FREE 500/month
1. rapidapi.com → search "Botometer Pro" → Subscribe to Free Plan
2. Copy `X-RapidAPI-Key`
3. Add to `.env`: `RAPIDAPI_KEY=your_key`
> Also needs `TWITTER_BEARER_TOKEN` to be set.

### SerpAPI (F-10 + F-12) — FREE 100/month
1. serpapi.com → Register (no credit card needed)
2. Dashboard → API Key → Copy
3. Add to `.env`: `SERPAPI_KEY=your_key`
> F-10 also works for free via Yandex (no key needed).

### IntelX OSINT (F-15) — FREE academic tier
1. intelx.io/account#api → Register
2. Select "Academic / Non-profit" plan during signup
3. After approval: Account → API → Copy Key
4. Add to `.env`: `INTELX_API_KEY=your_key`

### URLScan.io (F-17 link safety) — FREE 1000/day
1. urlscan.io/user/signup → Register
2. API Keys tab → Create key
3. Add to `.env`: `URLSCAN_API_KEY=your_key`

### VirusTotal (F-17 link safety) — FREE 500/day
1. virustotal.com/gui/join-us → Register
2. My Profile → API Key → Copy
3. Add to `.env`: `VIRUSTOTAL_API_KEY=your_key`

### NumVerify (phone carrier/VoIP) — FREE 100/day
1. numverify.com → Get Free API Key
2. Add to `.env`: `NUMVERIFY_API_KEY=your_key`

### BotSentinel — Coming May 1, 2026
Register now at botsentinel.com so you're ready when it launches.

---

## All 19 Analyzers

| Phase | ID | Feature | Keys Needed |
|---|---|---|---|
| 1 | F-01 | Username entropy + impersonation | None |
| 1 | F-02 | Name divergence + scam keywords | None |
| 1 | F-03 | Profile completeness + age | None |
| 1 | F-04 | Posting frequency (bot regularity) | None |
| 1 | F-05 | Engagement ratio anomaly | None |
| 1 | F-06 | Wayback Machine growth spike | None |
| 2 | F-07 | Twitter API v2 heuristics | TWITTER_BEARER_TOKEN (free) |
| 2 | F-08 | Social Blade history | SOCIALBLADE (free) |
| 2 | F-09 | Botometer score | RAPIDAPI_KEY (free) |
| 2 | F-10 | Reverse image (Yandex free + SerpAPI) | None / SERPAPI_KEY |
| 2 | F-11 | EmailRep profile email | None (100/day) |
| 2 | F-12 | SerpAPI Google Images | SERPAPI_KEY (free) |
| 3 | F-13 | Bio NLP scam detection | None |
| 3 | F-14 | Cross-platform username check | None |
| 3 | F-15 | OSINT: LeakCheck + HudsonRock + IntelX | None / INTELX_API_KEY |
| 3 | F-16 | Account age + velocity | None |
| 4 | F-17 | Link safety (URLScan + VirusTotal) | URLSCAN / VIRUSTOTAL (free) |
| 4 | F-18 | Content pattern / copy-paste | None |
| 4 | F-19 | Language + geo mismatch | None |

Plus: Email (FE-1 to FE-4) and Phone (FP-1, FP-2, FWA-1)

---

## Scoring

| Phase | Contribution |
|---|---|
| Phase 1 (130 raw pts) | Normalized → 0–100 base score |
| Phase 2 (optional APIs) | Up to +25 bonus |
| Phase 3 (OSINT/NLP) | Up to +15 bonus |
| Phase 4 (links/content) | Up to +10 bonus |
| **Total max** | **100** |

| Score | Level | Meaning |
|---|---|---|
| 0–29 | 🟢 Low | Likely legitimate |
| 30–59 | 🟡 Medium | Suspicious — investigate |
| 60–100 | 🔴 High | Strong fake/bot/fraud signal |

**Override rules:**
- 3+ strong signals → minimum 60
- Growth spike + ghost followers → minimum 70
- OSINT breach found → minimum 65
- Malicious link found → minimum 75

---

## Integration (other Aegis modules)

```python
import httpx

async def analyze(value: str, input_type: str, platform: str = None) -> dict:
    body = {"value": value, "input_type": input_type}
    if platform:
        body["platform"] = platform
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post("http://aegis-analyzer:8003/analyze", json=body)
    data = r.json()
    return {
        "score":   data["suspicion_score"],
        "level":   data["suspicion_level"],
        "flags":   data["flags_raised"][:5],
        "verdict": data.get("verdict", ""),
    }
```

---

## Troubleshooting

**Docker crash on startup:**
- Make sure you deleted ALL old files first
- Verify `app/scraper/router.py` exists (NOT `other.py`)
- Run: `docker compose down && docker compose up --build`

**Scraping returns limited data:**
- Instagram/TikTok increasingly block scrapers — try `force_refresh: true`
- Twitter works best with `TWITTER_BEARER_TOKEN` set
- Private profiles will always have limited data

**Phase 2 shows `available: false`:**
- Normal if API key not set — add key to `.env` then `docker compose restart`

**Redis unavailable:**
- Redis not starting? Check Docker Desktop → `aegis-redis` container
- App still works without Redis (just no caching)
