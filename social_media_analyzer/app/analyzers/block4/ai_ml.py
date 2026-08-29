"""
Block 4 — AI/ML Holistic Scoring
Consolidated: Ollama LLM, LLaVA Vision, sklearn RF, Stylometry, Aggregation
"""
import os, re, math, time, json, pickle, statistics, asyncio, logging
from typing import Any, Dict, List, Optional, Tuple
import httpx

from app.config import get_settings
from app.models import (
    OllamaHolisticResult, LlavaResult, SklearnResult, StylometryResult,
    FinalVerdict, RiskLevel, FraudType,
)
from data.patterns import EMOJI_RE, ROMAN_URDU_MARKERS

logger   = logging.getLogger(__name__)
settings = get_settings()


# ══════════════════════════════════════════════════════════════════════════════
#  OLLAMA CLIENT
# ══════════════════════════════════════════════════════════════════════════════
async def _ollama(
    prompt:  str,
    system:  Optional[str] = None,
    model:   Optional[str] = None,
    images:  Optional[List[str]] = None,
    timeout: int = 60,
) -> Tuple[Optional[Dict], int]:
    if not settings.ollama_enabled:
        return None, 0
    msgs: List[Dict] = []
    if system:
        msgs.append({"role": "system", "content": system})
    user_msg: Dict[str, Any] = {"role": "user", "content": prompt}
    if images:
        user_msg["images"] = images
    msgs.append(user_msg)

    payload = {
        "model":    model or settings.ollama_model,
        "format":   "json",
        "stream":   False,
        "options":  {"temperature": 0.05, "num_predict": 768},
        "messages": msgs,
    }
    t0 = time.time()
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.post(f"{settings.ollama_base_url}/api/chat", json=payload)
        ms  = int((time.time() - t0) * 1000)
        if r.status_code != 200:
            return None, ms
        raw = r.json().get("message", {}).get("content", "").strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1].lstrip("json").strip()
        return json.loads(raw), ms
    except json.JSONDecodeError as e:
        return None, int((time.time() - t0) * 1000)
    except Exception as e:
        logger.debug(f"[ollama] {e}")
        return None, int((time.time() - t0) * 1000)


async def ollama_holistic(
    username: Optional[str], bio: Optional[str],
    claimed_platform: Optional[str], claimed_location: Optional[str],
    followers: Optional[int], following: Optional[int],
    account_age_days: Optional[int], sample_posts: Optional[List[str]],
    is_verified: bool, all_flags: List[str],
) -> OllamaHolisticResult:

    posts_sec = ""
    if sample_posts:
        posts_sec = "\nSample Posts:\n" + "\n".join(
            f"  {i+1}. {p[:250]}" for i, p in enumerate(sample_posts[:5])
        )
    flags_sec = ""
    if all_flags:
        flags_sec = "\nDetected Flags:\n" + "\n".join(f"  - {f}" for f in all_flags[:15])

    prompt = f"""You are an expert AI fraud analyst (Aegis AI). Analyze this social media profile comprehensively.

=== PROFILE ===
Username:    {username or 'N/A'}
Platform:    {claimed_platform or 'N/A'}
Location:    {claimed_location or 'N/A'}
Followers:   {followers if followers is not None else 'N/A'}
Following:   {following if following is not None else 'N/A'}
Age:         {f"{account_age_days} days" if account_age_days else 'N/A'}
Verified:    {'Yes' if is_verified else 'No'}

Bio: "{bio[:600] if bio else 'None'}"
{posts_sec}{flags_sec}

=== TASK ===
Produce a comprehensive fraud verdict. Consider: scam language, behavioral signals,
authenticity, Pakistani-specific patterns (NADRA/FBR/Easypaisa), and all flags above.

Return ONLY this JSON (no extra text):
{{
  "scam_score": <0-100>,
  "fraud_type": "<impersonator|catfish|bot|scammer|political_bot|romance_scam|crypto_scam|account_seller|coordinated_inauthentic|legitimate|unknown>",
  "confidence": "<high|medium|low>",
  "red_flags": ["<flag1>", "<flag2>", "<flag3>"],
  "reasoning": "<3-4 sentence analysis>",
  "recommended_action": "<block|warn|monitor|none>"
}}"""

    parsed, ms = await _ollama(
        prompt,
        system="You are Aegis AI fraud analyst. Respond ONLY with valid JSON. No preamble.",
    )
    if not parsed:
        return OllamaHolisticResult(
            available=False, model=settings.ollama_model,
            error="Ollama unavailable or returned invalid JSON", latency_ms=ms,
        )
    return OllamaHolisticResult(
        available=True, model=settings.ollama_model,
        scam_score=int(parsed.get("scam_score", 0)),
        fraud_type=parsed.get("fraud_type", "unknown"),
        confidence=parsed.get("confidence", "low"),
        red_flags=parsed.get("red_flags", []),
        reasoning=parsed.get("reasoning", ""),
        recommended_action=parsed.get("recommended_action", "none"),
        latency_ms=ms,
    )


async def ollama_vision(
    image_base64: str, mime_type: str = "image/jpeg",
    username: Optional[str] = None,
) -> LlavaResult:
    if not settings.ollama_vision_enabled:
        return LlavaResult(available=False, model=settings.ollama_vision_model,
                           error="Vision disabled (OLLAMA_VISION_ENABLED=false)")

    ctx = f" for username '{username}'" if username else ""
    prompt = f"""Analyze this social media profile picture{ctx}.
Detect: AI-generated faces, stock photos, multiple people (catfish), cartoon avatars.

Return ONLY this JSON:
{{
  "is_ai_generated": <true|false|null>,
  "ai_confidence": <0-100>,
  "face_detected": <true|false>,
  "multiple_faces": <true|false>,
  "is_stock_photo": <true|false>,
  "is_cartoon_avatar": <true|false>,
  "red_flags": ["<concern1>"],
  "description": "<1-2 sentences>",
  "reasoning": "<authenticity assessment>"
}}"""

    parsed, ms = await _ollama(prompt, model=settings.ollama_vision_model,
                                images=[image_base64], timeout=90)
    if not parsed:
        return LlavaResult(available=False, model=settings.ollama_vision_model,
                           error="LLaVA unavailable or parse failed", latency_ms=ms)
    return LlavaResult(
        available=True, model=settings.ollama_vision_model,
        is_ai_generated=parsed.get("is_ai_generated"),
        ai_confidence=parsed.get("ai_confidence"),
        face_detected=parsed.get("face_detected"),
        multiple_faces=parsed.get("multiple_faces"),
        is_stock_photo=parsed.get("is_stock_photo"),
        is_cartoon_avatar=parsed.get("is_cartoon_avatar"),
        red_flags=parsed.get("red_flags", []),
        description=parsed.get("description", ""),
        reasoning=parsed.get("reasoning", ""),
        latency_ms=ms,
    )


async def ollama_health() -> Dict[str, Any]:
    if not settings.ollama_enabled:
        return {"status": "disabled"}
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{settings.ollama_base_url}/api/tags")
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            return {
                "status":             "healthy",
                "text_model_ready":   any(settings.ollama_model in m for m in models),
                "vision_model_ready": any(settings.ollama_vision_model.split(":")[0] in m for m in models),
                "available_models":   models,
            }
        return {"status": "error", "http": r.status_code}
    except Exception as e:
        return {"status": "unavailable", "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
#  STYLOMETRY
# ══════════════════════════════════════════════════════════════════════════════
def _syllables(word: str) -> int:
    word = word.lower().strip(".,!?;:")
    if len(word) <= 3: return 1
    count = len(re.findall(r"[aeiou]+", word))
    if word.endswith("e"): count = max(1, count - 1)
    return max(1, count)


def _tokens(text: str) -> List[str]:
    return re.findall(r"\b[a-zA-Z']+\b", text.lower())


def _sentences(text: str) -> List[str]:
    return [s.strip() for s in re.split(r"[.!?]+", text) if len(s.strip()) > 3]


def analyze_stylometry(bio: Optional[str], posts: Optional[List[str]]) -> StylometryResult:
    texts = []
    if bio:   texts.append(bio)
    if posts: texts.extend(posts[:10])
    if not texts:
        return StylometryResult(available=False, error="No text provided")

    combined = " ".join(texts)
    try:
        words = _tokens(combined)
        sents = _sentences(combined)
        if not words:
            return StylometryResult(available=False, error="No parseable words")

        # Lexical
        unique  = set(words)
        ttr     = len(unique) / len(words)
        avg_wl  = sum(len(w) for w in words) / len(words)
        freq: Dict[str, int] = {}
        for w in words: freq[w] = freq.get(w, 0) + 1
        hapax = sum(1 for c in freq.values() if c == 1) / max(len(unique), 1)
        top5  = sorted(freq.values(), reverse=True)[:5]
        rep   = sum(top5) / len(words)

        # Syntactic
        avg_sl   = (sum(len(_tokens(s)) for s in sents) / len(sents)) if sents else 0
        avg_syll = sum(_syllables(w) for w in words) / len(words)
        punct    = sum(1 for c in combined if c in ".,!?;:—") / max(len(combined), 1)
        cap_w    = [w for w in combined.split() if len(w) >= 3 and w.isupper() and w.isalpha()]
        cap_rate = len(cap_w) / max(len(combined.split()), 1)
        excl     = combined.count("!") / max(len(sents), 1)
        emojis   = EMOJI_RE.findall(combined)
        e_dens   = len(emojis) / max(len(combined.split()), 1)

        # Readability (Flesch)
        try:
            import textstat
            fre = textstat.flesch_reading_ease(combined)
            fog = textstat.gunning_fog(combined)
        except ImportError:
            asl = avg_sl; asw = avg_syll
            fre = round(206.835 - 1.015 * asl - 84.6 * asw, 2)
            fog = None

        # Cross-post uniformity
        uni = None
        if posts and len(posts) >= 3:
            lens = [len(_tokens(p)) for p in posts]
            ttrs = [len(set(_tokens(p))) / max(len(_tokens(p)), 1) for p in posts]
            lc   = statistics.stdev(lens) / statistics.mean(lens) if statistics.mean(lens) > 0 else 1
            tc   = statistics.stdev(ttrs) / statistics.mean(ttrs) if statistics.mean(ttrs) > 0 else 1
            uni  = round(1.0 - min((lc + tc) / 2, 1.0), 4)

        # Bot score
        bscore, bflags = 0, []
        if ttr < 0.2:
            bscore += 15; bflags.append(f"low_vocabulary_diversity:ttr={ttr:.2f}")
        elif ttr < 0.35:
            bscore += 8
        if rep > 0.5:
            bscore += 12; bflags.append(f"high_repetition:{rep:.2f}")
        if excl > 3:
            bscore += 10; bflags.append(f"excessive_exclamations:{excl:.1f}/sent")
        if cap_rate > 0.15:
            bscore += 8; bflags.append(f"excessive_caps:{cap_rate:.2f}")
        if e_dens > 0.3:
            bscore += 8; bflags.append(f"very_high_emoji_density:{e_dens:.2f}")
        if uni and uni > 0.85:
            bscore += 20; bflags.append(f"template_like_posts:uniformity={uni:.2f}")
        elif uni and uni > 0.70:
            bscore += 10

        return StylometryResult(
            available=True,
            avg_word_length=round(avg_wl, 2),
            avg_sentence_length=round(avg_sl, 2),
            vocabulary_richness=round(ttr, 4),
            flesch_reading_ease=round(fre, 2),
            gunning_fog=round(fog, 2) if fog else None,
            punctuation_density=round(punct, 4),
            capitalization_rate=round(cap_rate, 4),
            text_uniformity_score=uni,
            repetition_score=round(rep, 4),
            stylometry_bot_score=min(bscore, 100),
            flags=bflags,
        )
    except Exception as e:
        return StylometryResult(available=False, error=str(e))


# ══════════════════════════════════════════════════════════════════════════════
#  SKLEARN — RandomForestClassifier
# ══════════════════════════════════════════════════════════════════════════════
FEATURE_NAMES = [
    "followers", "following", "ff_ratio", "account_age_days",
    "posts_count", "bio_length", "bio_scam_score",
    "is_verified", "has_phone_in_bio", "uses_scheduler",
    "engagement_rate", "copy_paste_score", "platforms_found", "breach_count",
    "ttr", "avg_word_len", "hapax_ratio", "repetition",
    "text_uniformity", "excl_density", "emoji_density",
    "block1_score", "block2_score", "block3_score",
]

_model = None
_model_meta: Dict[str, Any] = {}


def _safe(v, d=0.0) -> float:
    try: return float(v) if v is not None else float(d)
    except: return float(d)


def _make_vector(**kw) -> List[float]:
    f  = _safe(kw.get("followers"))
    fo = _safe(kw.get("following"))
    return [
        f, fo, f / max(fo, 1),
        _safe(kw.get("account_age_days")),
        _safe(kw.get("posts_count")),
        _safe(kw.get("bio_length")),
        _safe(kw.get("bio_scam_score")),
        1.0 if kw.get("is_verified") else 0.0,
        1.0 if kw.get("has_phone_in_bio") else 0.0,
        1.0 if kw.get("uses_scheduler") else 0.0,
        _safe(kw.get("engagement_rate")),
        _safe(kw.get("copy_paste_score")),
        _safe(kw.get("platforms_found")),
        _safe(kw.get("breach_count")),
        _safe(kw.get("ttr"), 0.5),
        _safe(kw.get("avg_word_len"), 4.5),
        _safe(kw.get("hapax_ratio"), 0.5),
        _safe(kw.get("repetition"), 0.2),
        _safe(kw.get("text_uniformity"), 0.5),
        _safe(kw.get("excl_density"), 0.2),
        _safe(kw.get("emoji_density")),
        _safe(kw.get("block1_score")),
        _safe(kw.get("block2_score")),
        _safe(kw.get("block3_score")),
    ]


def load_sklearn_model() -> bool:
    global _model, _model_meta
    path = settings.sklearn_model_path
    if not os.path.exists(path): return False
    try:
        with open(path, "rb") as f:
            data = pickle.load(f)
        _model      = data["model"]
        _model_meta = data.get("meta", {})
        logger.info(f"[sklearn] Model loaded v{_model_meta.get('version','?')}")
        return True
    except Exception as e:
        logger.warning(f"[sklearn] Load failed: {e}")
        return False


def train_sklearn(samples) -> Dict[str, Any]:
    global _model, _model_meta
    try:
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import f1_score, accuracy_score
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline
    except ImportError:
        return {"success": False, "message": "pip install scikit-learn"}

    X = [_make_vector(
        followers=s.followers, following=s.following, account_age_days=s.account_age_days,
        posts_count=s.posts_count, bio_length=s.bio_length, bio_scam_score=s.bio_scam_score,
        is_verified=s.is_verified, has_phone_in_bio=s.has_phone_in_bio,
        uses_scheduler=s.uses_scheduler, engagement_rate=s.engagement_rate,
        copy_paste_score=s.copy_paste_score, platforms_found=s.platforms_found,
        breach_count=s.breach_count, block1_score=s.block1_score,
        block2_score=s.block2_score, block3_score=s.block3_score,
    ) for s in samples]
    y = [s.label for s in samples]

    if len(set(y)) < 2:
        return {"success": False, "samples_used": len(samples),
                "message": "Need both fake (1) and real (0) samples", "feature_count": 0}

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    pipe = Pipeline([("scaler", StandardScaler()),
                     ("clf", RandomForestClassifier(
                         n_estimators=200, max_depth=12, min_samples_split=3,
                         class_weight="balanced", random_state=42, n_jobs=-1))])
    pipe.fit(X_tr, y_tr)
    y_pred = pipe.predict(X_te)
    acc = accuracy_score(y_te, y_pred)
    f1  = f1_score(y_te, y_pred, average="binary")
    imps = pipe.named_steps["clf"].feature_importances_
    fi   = sorted(zip(FEATURE_NAMES, imps), key=lambda x: -x[1])

    os.makedirs(os.path.dirname(settings.sklearn_model_path), exist_ok=True)
    meta = {"version": f"1.0.{len(samples)}", "accuracy": round(acc, 4),
            "f1": round(f1, 4), "samples": len(samples),
            "feature_importances": [(n, round(float(v), 4)) for n, v in fi[:10]]}
    with open(settings.sklearn_model_path, "wb") as f:
        pickle.dump({"model": pipe, "meta": meta}, f)

    _model = pipe; _model_meta = meta
    return {"success": True, "samples_used": len(samples), "accuracy": round(acc, 4),
            "f1_score": round(f1, 4), "feature_count": len(FEATURE_NAMES),
            "model_path": settings.sklearn_model_path,
            "message": f"Trained successfully. Accuracy={acc:.1%}, F1={f1:.3f}"}


def sklearn_predict(**kw) -> SklearnResult:
    global _model
    if not settings.sklearn_enabled:
        return SklearnResult(available=False, note="sklearn disabled")
    if _model is None:
        if not load_sklearn_model():
            return SklearnResult(available=False,
                                  note="No model — POST /train/sklearn first")
    try:
        t0   = time.time()
        vec  = [_make_vector(**kw)]
        prob = _model.predict_proba(vec)[0]
        fake_p = float(prob[1]) if len(prob) > 1 else float(prob[0])
        ms   = int((time.time() - t0) * 1000)
        fi   = _model_meta.get("feature_importances", [])[:5]
        return SklearnResult(
            available=True,
            model_version=_model_meta.get("version", "?"),
            fraud_probability=round(fake_p, 4),
            predicted_class="fake" if fake_p > 0.5 else "real",
            feature_count=len(FEATURE_NAMES),
            top_features=[{"name": n, "importance": v} for n, v in fi],
            latency_ms=ms,
        )
    except Exception as e:
        return SklearnResult(available=False, error=str(e))


# ══════════════════════════════════════════════════════════════════════════════
#  SCORE AGGREGATION
# ══════════════════════════════════════════════════════════════════════════════
# Fraud type keyword → enum
_FTYPE_MAP = {
    "impersonator":            FraudType.IMPERSONATOR,
    "catfish":                 FraudType.CATFISH,
    "bot":                     FraudType.BOT,
    "scammer":                 FraudType.SCAMMER,
    "political_bot":           FraudType.POLITICAL_BOT,
    "romance_scam":            FraudType.ROMANCE_SCAM,
    "crypto_scam":             FraudType.CRYPTO_SCAM,
    "account_seller":          FraudType.ACCOUNT_SELLER,
    "coordinated_inauthentic": FraudType.COORDINATED,
    "legitimate":              FraudType.LEGITIMATE,
}

_FLAG_HINTS = {
    "impersonat":  FraudType.IMPERSONATOR,
    "nadra":       FraudType.SCAMMER,
    "easypaisa":   FraudType.SCAMMER,
    "fbr":         FraudType.SCAMMER,
    "bot":         FraudType.BOT,
    "automated":   FraudType.BOT,
    "purchased":   FraudType.BOT,
    "follower_spike": FraudType.BOT,
    "giveaway":    FraudType.CRYPTO_SCAM,
    "crypto":      FraudType.CRYPTO_SCAM,
    "forex":       FraudType.SCAMMER,
    "romance":     FraudType.ROMANCE_SCAM,
    "cib_":        FraudType.COORDINATED,
    "coordinated": FraudType.COORDINATED,
    "catfish":     FraudType.CATFISH,
    "dark_web":    FraudType.SCAMMER,
    "breach":      FraudType.SCAMMER,
    "infostealer": FraudType.SCAMMER,
}

W = {   # Aggregation weights
    "block1": 0.9, "block2": 1.0, "block3": 1.2,
    "ollama": 1.3, "vision": 1.2, "sklearn": 1.1, "stylo": 0.7,
}


def _resolve_fraud_type(ollama_type: Optional[str], all_flags: List[str]) -> FraudType:
    if ollama_type and ollama_type not in ("unknown", "legitimate"):
        return _FTYPE_MAP.get(ollama_type, FraudType.UNKNOWN)
    for flag in all_flags:
        fl = flag.lower()
        for kw, ft in _FLAG_HINTS.items():
            if kw in fl:
                return ft
    return FraudType.UNKNOWN


def aggregate(
    username:          Optional[str],
    claimed_platform:  Optional[str],
    block1_score:      Optional[int],
    block2_score:      Optional[int],
    block3_score:      Optional[int],
    ollama_result:     Optional[OllamaHolisticResult],
    vision_result:     Optional[LlavaResult],
    sklearn_result:    Optional[SklearnResult],
    stylo_result:      Optional[StylometryResult],
    all_flags:         List[str],
    analysis_start:    float,
    blocks_run:        List[str],
) -> FinalVerdict:
    wsum = wdiv = 0.0

    def _add(score: Optional[int], key: str):
        nonlocal wsum, wdiv
        if score is not None:
            wsum += score * W[key]
            wdiv += W[key]

    _add(block1_score, "block1")
    _add(block2_score, "block2")
    _add(block3_score, "block3")

    ollama_s = vis_s = sk_s = sty_s = None

    if ollama_result and ollama_result.available and ollama_result.scam_score is not None:
        ollama_s = ollama_result.scam_score
        _add(ollama_s, "ollama")
        all_flags.extend(f"ollama:{f}" for f in (ollama_result.red_flags or [])[:3])

    if vision_result and vision_result.available:
        vs = 0
        if vision_result.is_ai_generated:   vs += 35
        if vision_result.is_stock_photo:    vs += 20
        if vision_result.multiple_faces:    vs += 15
        vs += len(vision_result.red_flags) * 5
        vis_s = min(vs, 100)
        _add(vis_s, "vision")
        if vision_result.is_ai_generated:
            all_flags.append(f"llava_ai_face:confidence={vision_result.ai_confidence}")

    if sklearn_result and sklearn_result.available and sklearn_result.fraud_probability is not None:
        sk_s = int(sklearn_result.fraud_probability * 100)
        _add(sk_s, "sklearn")
        if sklearn_result.predicted_class == "fake":
            all_flags.append(f"sklearn_fake:{sklearn_result.fraud_probability:.0%}")

    if stylo_result and stylo_result.available and stylo_result.stylometry_bot_score is not None:
        sty_s = stylo_result.stylometry_bot_score
        _add(sty_s, "stylo")
        all_flags.extend(stylo_result.flags[:2])

    final = int(min(100, wsum / max(wdiv, 1.0)))

    if final >= 70:   risk = RiskLevel.CRITICAL
    elif final >= 50: risk = RiskLevel.HIGH
    elif final >= 30: risk = RiskLevel.MEDIUM
    elif final >= 10: risk = RiskLevel.LOW
    else:             risk = RiskLevel.CLEAN

    fraud_type = _resolve_fraud_type(
        ollama_result.fraud_type if ollama_result and ollama_result.available else None,
        all_flags,
    )

    sources_used = sum(1 for s in [block1_score, block2_score, block3_score,
                                    ollama_s, vis_s, sk_s, sty_s] if s is not None)
    confidence = ("high"   if sources_used >= 4 and (final >= 60 or final <= 15) else
                  "medium" if sources_used >= 3 and (final >= 45 or final <= 25) else "low")

    top_flags  = sorted(set(all_flags), key=len, reverse=True)[:8]
    rec_map    = {
        RiskLevel.CRITICAL: "Block or suspend — critical fraud confirmed.",
        RiskLevel.HIGH:     "Flag for review and restrict reach.",
        RiskLevel.MEDIUM:   "Monitor and consider limiting visibility.",
        RiskLevel.LOW:      "Log and watch — low risk, no immediate action.",
        RiskLevel.CLEAN:    "No action — profile appears legitimate.",
    }
    ollama_action = (ollama_result.recommended_action
                     if ollama_result and ollama_result.available else None)
    action_override = {
        "block":   "Block — strong evidence of fraudulent activity.",
        "warn":    "Warn user and restrict actions pending review.",
        "monitor": "Monitor for further suspicious activity.",
    }
    recommendation = action_override.get(ollama_action or "", rec_map[risk])

    if risk == RiskLevel.CLEAN:
        summary = f"Profile '{username}' appears authentic. No significant signals detected."
    else:
        summary = (f"Profile '{username}' scores {final}/100 ({risk.value} risk). "
                   f"Fraud type: {fraud_type.value}. "
                   f"Top signal: {top_flags[0] if top_flags else 'none'}.")

    return FinalVerdict(
        block1_score=block1_score, block2_score=block2_score, block3_score=block3_score,
        block4_ollama_score=ollama_s, block4_vision_score=vis_s,
        block4_sklearn_score=sk_s, block4_stylo_score=sty_s,
        final_score=final, risk_level=risk,
        fraud_type=fraud_type, fraud_type_label=fraud_type.value.upper(),
        confidence=confidence, top_flags=top_flags,
        all_flags=list(set(all_flags)),
        summary=summary, recommendation=recommendation,
        analysis_ms=int((time.time() - analysis_start) * 1000),
        blocks_run=blocks_run,
    )
