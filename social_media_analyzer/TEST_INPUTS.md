# Aegis AI v4 — Manual Test Inputs
# Post these via Swagger UI at http://localhost:8003/docs → POST /analyze

---

## SOCIAL MEDIA — Real accounts to verify Phase 1–4

### 1. Elon Musk — Twitter/X (expect: Low score, famous verified account)
```json
{"value":"elonmusk","input_type":"social_media","platform":"twitter"}
```
**Expected:** Low–Medium score. F-01 may flag high follower count. F-07 should show Trustworthy/Acceptable (needs TWITTER_BEARER_TOKEN). Verified account, complete profile.

---

### 2. Cristiano Ronaldo — Instagram (expect: Low, famous verified)
```json
{"value":"cristiano","input_type":"social_media","platform":"instagram"}
```
**Expected:** Low score. Very complete profile. Extremely high engagement baseline. F-10 reverse image may show many matches (stock/press photos — that's normal for celebrities).

---

### 3. Khaby Lame — TikTok (expect: Low, most-followed TikTok account)
```json
{"value":"khaby.lame","input_type":"social_media","platform":"tiktok"}
```
**Expected:** Low score. Very high followers, consistent posting pattern. F-19 may detect Italian/French.

---

### 4. MrBeast — YouTube (expect: Low)
```json
{"value":"MrBeast","input_type":"social_media","platform":"youtube"}
```
**Expected:** Low. Large subscriber count retrieved. Complete profile.

---

### 5. Test a suspicious/fake account pattern — Twitter
```json
{"value":"invest_signal99","input_type":"social_media","platform":"twitter"}
```
**Expected:** Medium–High score. F-01 flags trailing digits. If account exists: check F-04 posting pattern, F-05 engagement.

---

### 6. Imran Khan — Twitter (Pakistani politician — tests language/geo)
```json
{"value":"ImranKhanPTI","input_type":"social_media","platform":"twitter"}
```
**Expected:** Low score. F-19 may detect mixed Arabic/Latin. F-07 requires TWITTER_BEARER_TOKEN.

---

### 7. Test blank/random username (expect: High — account unlikely to exist)
```json
{"value":"xzxz9988mfkqw77","input_type":"social_media","platform":"twitter"}
```
**Expected:** High score from F-01 (high entropy), incomplete profile (F-03). No data.

---

## EMAIL — Verification inputs

### 8. Legitimate free email (expect: Low 🟢)
```json
{"value":"test.user@gmail.com","input_type":"email"}
```
**Expected:** Low. Valid format. MX records exist. Free provider. No disposable flag.

---

### 9. Disposable — mailinator (expect: High 🔴)
```json
{"value":"randomuser@mailinator.com","input_type":"email"}
```
**Expected:** High. FE-2 = is_disposable: true. Score ≥ 60.

---

### 10. Disposable — yopmail (expect: High 🔴)
```json
{"value":"anything@yopmail.com","input_type":"email"}
```
**Expected:** High. FE-2 flags as disposable. Score ≥ 60.

---

### 11. Disposable — 10minutemail (expect: High 🔴)
```json
{"value":"test@10minutemail.com","input_type":"email"}
```
**Expected:** High. Disposable domain detected.

---

### 12. Completely invalid email (expect: High 🔴)
```json
{"value":"notanemail","input_type":"email"}
```
**Expected:** High. FE-1 = is_valid_format: false. Score ≥ 60.

---

### 13. Nonexistent domain (expect: Medium–High)
```json
{"value":"user@thisdomain-does-not-exist-12345.com","input_type":"email"}
```
**Expected:** Medium–High. FE-1 = domain_exists: false. No MX record.

---

### 14. Business email (expect: Low–Medium)
```json
{"value":"contact@microsoft.com","input_type":"email"}
```
**Expected:** Low. Valid domain. MX records present. Not disposable.

---

## PHONE — Verification inputs

### 15. Valid Pakistan mobile (expect: Valid 🟢)
```json
{"value":"+923001234567","input_type":"phone"}
```
**Expected:** Valid. country_code: PK. number_type: mobile. Low score.

---

### 16. Valid UK number (expect: Valid 🟢)
```json
{"value":"+442071234567","input_type":"phone"}
```
**Expected:** Valid. country_code: GB. number_type: fixed_line.

---

### 17. Valid US number (expect: Valid 🟢)
```json
{"value":"+12025551234","input_type":"phone"}
```
**Expected:** Valid. country_code: US.

---

### 18. Invalid/too short number (expect: Invalid 🔴)
```json
{"value":"+1234","input_type":"phone"}
```
**Expected:** Invalid. is_valid: false. Score ≥ 30.

---

### 19. Fake/random digits (expect: Invalid 🔴)
```json
{"value":"00000000000","input_type":"phone"}
```
**Expected:** Invalid. Not a real number.

---

## WHATSAPP — Verification inputs

### 20. Valid WhatsApp PK (expect: link generated 🟢)
```json
{"value":"+923001234567","input_type":"whatsapp"}
```
**Expected:** number_valid: true. whatsapp_link: "https://wa.me/923001234567"

---

### 21. Valid WhatsApp UK
```json
{"value":"+447911123456","input_type":"whatsapp"}
```
**Expected:** number_valid: true. whatsapp_link: "https://wa.me/447911123456"

---

### 22. Invalid WhatsApp number
```json
{"value":"0000","input_type":"whatsapp"}
```
**Expected:** number_valid: false.

---

## ADVANCED — Phase 4 tests (need API keys)

### 23. Skip phase 2+3, only Phase 4 (link safety in bio)
```json
{"value":"cristiano","input_type":"social_media","platform":"instagram","run_phase2":false,"run_phase3":false,"run_phase4":true}
```

### 24. Disable Wayback Machine (faster — no ~20s wait)
```json
{"value":"elonmusk","input_type":"social_media","platform":"twitter","run_wayback":false}
```

### 25. Force cache refresh
```json
{"value":"elonmusk","input_type":"social_media","platform":"twitter","force_refresh":true}
```

---

## What to check in results

| Field | What it tells you |
|---|---|
| `suspicion_score` | 0–100 overall risk |
| `suspicion_level` | Low / Medium / High |
| `flags_raised` | Specific reasons for suspicion |
| `score_breakdown` | Per-analyzer contribution |
| `data_limitations` | Why some analyses were skipped |
| `scraped_successfully` | Whether public data was obtained |
| `phase2_ran` / `phase3_ran` / `phase4_ran` | Which phases executed |
| `f01_username_entropy.pattern_flags` | Username red flags |
| `f03_profile_completeness.missing_fields` | What's missing from profile |
| `f04_posting_frequency.is_bot_regular` | Machine-regular posting pattern |
| `f05_engagement_ratio.anomaly_type` | ghost_followers / like_farming |
| `f13_bio_nlp.flags` | Scam keywords in bio |
| `f17_link_safety.malicious_links` | Bad links found (needs URLScan/VT keys) |
