"""app/handlers/orchestrator.py — Main message processing pipeline.

FIXES applied:
  BUG-001: df_result vs result in _handle_deepfake_image
  BUG-002: _static_cyber_answer was missing — now defined
  BUG-003: double append_history call removed
  BUG-004: wrong ollama import path fixed (app.llm → app.router)
  BUG-005: re module import added
  BUG-006: last_scan / last_module scope fixed in _dispatch
  BUG-007: moviepy top-level import moved inside function

ENHANCEMENTS applied:
  ENH-001: Consistent Ollama explanation format (via ollama_client)
  ENH-002: Follow-up for ALL module types (credential, profile, QR, deepfake)
  ENH-003: Prompt-when-missing for all credential types
  ENH-004: Cross-type mismatch detection
  ENH-005: Cyber Q&A always different via answer_cyber_qa()
  ENH-006: Parallel execution for both/all (asyncio.gather confirmed)
  ENH-007: General menu formatting
  ENH-008: Bot intro unique each time
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

from app.config import get_settings
from app.router.extractor import extract, ExtractedEntities
from app.router.intent import classify, Module, RouteDecision
from app.router import dispatcher as api
from app.formatters import responses as fmt
from app.router.ollama_client import (
    _ask as _ask_ollama,
    classify_smishing, classify_urdu, classify_followup,
    is_ollama_available, explain_result, detect_social_platform,
    explain_followup, answer_cyber_qa,
)
from app.services.profile_intelligence import compute_unified_verdict
from app.services.username_intelligence import score_and_rank as username_score_and_rank
from app.services.smishing_engine import analyse_smishing, format_smishing_result
from app.services.long_term_memory import (
    store_long_term, get_long_term_summary,
    check_previously_seen, format_30day_history,
)
from app.services.deepfake_service import (
    analyze_image_bytes, analyze_image_url, analyze_video_bytes,
    submit_video_async, poll_video_job, health_check as deepfake_health,
    format_deepfake_image, format_deepfake_video,
    format_deepfake_no_face, format_deepfake_job_submitted,
    format_deepfake_result,
)
from app.session import (
    get_or_create_session, update_session, delete_session,
    append_history, store_last_scan, check_rate_limit, ConvState,
)

settings = get_settings()
logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_image_url(url: str) -> bool:
    ext = re.search(r'\.([a-zA-Z0-9]+)(?:\?|$)', url)
    if ext and ext.group(1).lower() in {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff'}:
        return True
    image_domains = {
        'thispersondoesnotexist.com', 'generated.photos', 'lensa.ai',
        'midjourney.com', 'openai.com', 'ideogram.ai', 'stablecog.com',
    }
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.lower().replace('www.', '')
    if any(d in domain for d in image_domains):
        return True
    path = urlparse(url).path.lower()
    return any(kw in path for kw in ['image', 'photo', 'picture', 'img', 'assets', 'uploads', 'media'])


async def _handle_no_face_image(phone: str, result: dict, decision: RouteDecision) -> str:
    explanation = await explain_result(
        "deepfake", "no_face", result,
        user_question=decision.context or decision.raw_text,
        custom_facts="No human face detected in the image. Deepfake analysis requires a clear face to work."
    )
    if not explanation:
        explanation = (
            "I couldn't detect a human face in this image.\n"
            "Verdict: Cannot analyse.\n"
            "Action: Please send a clear photo showing a person's face."
        )
    return f"👤 *No Face Detected*\n\n{explanation}"


async def _handle_no_face_video(phone: str, result: dict, decision: RouteDecision) -> str:
    explanation = await explain_result(
        "deepfake", "no_face", result,
        user_question=decision.context or decision.raw_text,
        custom_facts="No human face detected in the video. Deepfake analysis requires a clear face to work."
    )
    if not explanation:
        explanation = (
            "I couldn't detect a human face in this video.\n"
            "Verdict: Cannot analyse.\n"
            "Action: Please send a clear video showing a person's face."
        )
    return f"👤 *No Face Detected*\n\n{explanation}"


async def _extract_first_frame(video_bytes: bytes) -> Optional[str]:
    """Extract first frame from video bytes and return as base64 JPEG."""
    try:
        import io
        from moviepy.editor import VideoFileClip  # BUG-007: import inside function
        from PIL import Image
        import base64
        with io.BytesIO(video_bytes) as buffer:
            clip = VideoFileClip(buffer, audio=False)
            if clip.duration > 0:
                frame = clip.get_frame(0)
                img = Image.fromarray(frame)
                img_byte_arr = io.BytesIO()
                img.save(img_byte_arr, format='JPEG')
                return base64.b64encode(img_byte_arr.getvalue()).decode()
            clip.close()
    except Exception as e:
        logger.warning(f"Frame extraction failed: {e}")
    return None


async def _handle_deepfake_image(phone: str, df_result: dict, session: dict, decision: RouteDecision) -> str:
    """Handle an image that contains a face (deepfake analysis). BUG-001 fixed."""
    if df_result.get("module_unavailable"):
        return fmt.format_module_unavailable("Deepfake Detector")

    face_info = df_result.get("face_info", {})
    if face_info.get("faces_detected", 0) == 0:
        return await _handle_no_face_image(phone, df_result, decision)  # BUG-001: was `result`

    human_exp = await explain_result(
        "deepfake", df_result.get("overall_risk_level", ""), df_result,
        user_question=decision.context or decision.raw_text
    )
    reply = format_deepfake_image(df_result, human_explanation=human_exp or "")

    await store_last_scan(
        phone, "deepfake", df_result,
        df_result.get("overall_risk_level", ""),
        df_result.get("all_flags", []),
        original_input="[image]", item_scanned="image"
    )
    return reply


# BUG-002: _static_cyber_answer was missing — now defined
def _static_cyber_answer(topic: str) -> str:
    """Static cyber Q&A fallback when Ollama is unavailable."""
    topic_lower = topic.lower()
    if any(w in topic_lower for w in ["phish", "phishing"]):
        return (
            "🛡️ *Phishing* is when criminals create fake websites, emails, or messages "
            "pretending to be your bank, telecom, or government to steal your login details.\n\n"
            "*Verdict:* A major threat in Pakistan — JazzCash, HBL, and NADRA impersonation are common.\n"
            "*Action:* Never click links in unexpected SMS/WhatsApp messages. Always type the official URL directly."
        )
    if any(w in topic_lower for w in ["password", "strong password"]):
        return (
            "🔐 A *strong password* is at least 12 characters long and mixes uppercase, lowercase, "
            "numbers, and special characters (like @, !, #).\n\n"
            "*Verdict:* Weak passwords are the #1 cause of account takeovers.\n"
            "*Action:* Use a password manager and enable 2FA on all accounts."
        )
    if any(w in topic_lower for w in ["2fa", "two factor", "2 factor", "otp"]):
        return (
            "🔑 *Two-Factor Authentication (2FA)* adds a second verification step when logging in — "
            "usually a code sent to your phone or generated by an app.\n\n"
            "*Verdict:* Even if someone steals your password, 2FA stops them getting in.\n"
            "*Action:* Enable 2FA on WhatsApp, Gmail, and your bank app right now."
        )
    if any(w in topic_lower for w in ["vpn"]):
        return (
            "🌐 A *VPN* (Virtual Private Network) encrypts your internet connection and hides your "
            "location from websites and your ISP.\n\n"
            "*Verdict:* Useful on public WiFi but does not make you anonymous or protect against malware.\n"
            "*Action:* Use a trusted paid VPN (ProtonVPN, Mullvad) — free VPNs often sell your data."
        )
    if any(w in topic_lower for w in ["deepfake", "deep fake", "ai generated"]):
        return (
            "🎭 *Deepfakes* are AI-generated videos or images that replace a real person's face with "
            "someone else's. They are increasingly used for fraud and disinformation.\n\n"
            "*Verdict:* Deepfake scams targeting voice and face are growing rapidly in Pakistan.\n"
            "*Action:* Never transfer money based on a video call alone — call back on a known number."
        )
    if any(w in topic_lower for w in ["malware", "virus", "trojan", "spyware"]):
        return (
            "🦠 *Malware* is malicious software — including viruses, trojans, and spyware — "
            "designed to steal data, damage files, or spy on you.\n\n"
            "*Verdict:* Most malware enters through infected downloads, fake apps, or phishing links.\n"
            "*Action:* Keep your OS updated, avoid unofficial app stores, and never click suspicious links."
        )
    if any(w in topic_lower for w in ["sim swap", "sim hack"]):
        return (
            "📱 *SIM swapping* is when a fraudster convinces your telecom to transfer your number "
            "to their SIM — giving them access to all your OTP/2FA codes.\n\n"
            "*Verdict:* A serious threat — banks and crypto accounts are primary targets.\n"
            "*Action:* Add a SIM lock PIN through your carrier and use authenticator apps instead of SMS 2FA."
        )
    # Generic fallback
    return (
        "🛡️ *Cybersecurity Tip*\n\n"
        "Stay safe online by:\n"
        "• Never sharing OTPs, passwords, or CNIC with anyone\n"
        "• Verifying senders before clicking links\n"
        "• Enabling 2FA on all accounts\n\n"
        "*Action:* Report scams to FIA Cyber Crime: nia.gov.pk / 0800-55555"
    )


# ── Main entry point ──────────────────────────────────────────────────────────

async def handle_message(
    phone: str,
    text: str,
    media_type: Optional[str] = None,
    media_id: Optional[str] = None,
    message_id: str = "",
) -> str:
    if not await check_rate_limit(phone, "global", limit=30, window_seconds=60):
        return fmt.RATE_LIMIT_MSG

    session = await get_or_create_session(phone)

    # Pre-process button tap quoted text
    if text and "— what would you like to do?" in text:
        opts_in_session = session.get("disambiguation_options", {})
        for key, opt_list in opts_in_session.items():
            if len(opt_list) >= 3:
                desc = str(opt_list[2]).lower()
                if desc[:15] in text.lower() or str(key) in text.lower():
                    text = str(key)
                    break
        else:
            entity_match = re.match(r'^[\s]*([\w.]+)', text.strip())
            if entity_match:
                text = entity_match.group(1)

    # Normalize multi-line messages → single line (WhatsApp may send \n)
    if text:
        text = re.sub(r'\s*\n\s*', ' ', text).strip()
        text = re.sub(r'  +', ' ', text)

    # Typo correction for common first-word typos
    _TYPO_MAP = {
        r'^heck\b': 'check',
        r'^chek\b': 'check',
        r'^chekc\b': 'check',
        r'^chcek\b': 'check',
        r'^chec\b': 'check',
        r'^scna\b': 'scan',
        r'^sacan\b': 'scan',
        r'^scann\b': 'scan',
        r'^veryify\b': 'verify',
        r'^verift\b': 'verify',
        r'^is this\b': 'is this',  # keep as-is
    }
    if text:
        for pattern, replacement in _TYPO_MAP.items():
            fixed = re.sub(pattern, replacement, text, count=1, flags=re.IGNORECASE)
            if fixed != text:
                text = fixed
                break

    # Download image bytes if media present
    image_b64 = None
    video_b64 = None
    if media_type == "image" and media_id:
        image_b64 = await _download_image_b64(media_id)
    elif media_type == "video" and media_id:
        video_b64 = await _download_image_b64(media_id)   # same download, different flag

    # Extract entities
    ent = extract(text or "", media_type=media_type)
    if image_b64:
        ent.has_image = True
    if video_b64:
        ent.has_video = True

    # ── ASYNC VIDEO SCAN SYSTEM ──────────────────────────────────────────────
    # When video is present, start an async scan, return a scan ID immediately,
    # and send the result when user follows up with the ID or a followup phrase.
    if video_b64:
        import uuid, asyncio as _asyncio
        scan_id = str(uuid.uuid4())[:8].upper()
        pending = session.get("_pending_video_scans", {})

        # Store video bytes in session for retrieval
        pending[scan_id] = {
            "video_b64": video_b64,
            "text": text or "",
            "status": "processing",
            "result": None,
            "timestamp": __import__("time").time(),
        }
        await update_session(phone, _pending_video_scans=pending)

        # Start background analysis
        async def _run_video_scan(p, sid, vb64, txt, sess):
            try:
                import base64 as _b64
                media_bytes = _b64.b64decode(vb64)
                result = await analyze_video_bytes(media_bytes)
                sess2 = await get_or_create_session(p)
                scans = sess2.get("_pending_video_scans", {})
                if sid in scans:
                    if result.get("module_unavailable"):
                        scans[sid]["status"] = "error"
                        scans[sid]["error_msg"] = "Deepfake service unavailable"
                    else:
                        face_info = result.get("face_info", {})
                        if face_info.get("faces_detected", 0) == 0:
                            scans[sid]["status"] = "no_face"
                        else:
                            scans[sid]["status"] = "done"
                        scans[sid]["result"] = result
                    await update_session(p, _pending_video_scans=scans)
            except Exception as e:
                sess2 = await get_or_create_session(p)
                scans = sess2.get("_pending_video_scans", {})
                if sid in scans:
                    scans[sid]["status"] = "error"
                    scans[sid]["error_msg"] = str(e)
                    await update_session(p, _pending_video_scans=scans)

        _asyncio.create_task(_run_video_scan(phone, scan_id, video_b64, text or "", session))

        return (
            f"🎬 *Video Received — Deepfake Analysis Started*\n\n"
            f"📋 Scan ID: `{scan_id}`\n\n"
            f"I'm analysing your video for deepfake manipulation. This may take 15–60 seconds.\n\n"
            f"You can:\n"
            f"• Ask me something else while you wait\n"
            f"• Send `{scan_id}` or ask *'is the scan done'* to get your result\n"
            f"• I'll also tell you when it's ready if you ask a followup"
        )

    # ── CHECK IF USER IS ASKING ABOUT A PENDING VIDEO SCAN ───────────────────
    _video_followup_phrases = {
        "is the scan done", "is it done", "is the video done", "scan complete",
        "show me the result", "share the result", "what did you find",
        "is the analysis done", "is the deepfake done", "finished",
        "is it finished", "any results", "are we done",
        "is the scanning done", "is video scanning done", "results ready",
    }
    _text_lower_check = (text or "").lower().strip()
    pending_scans = session.get("_pending_video_scans", {})
    if pending_scans:
        # Check if text is a scan ID
        _clean_text = _text_lower_check.upper().strip()
        _matched_id = None
        if _clean_text in pending_scans:
            _matched_id = _clean_text
        else:
            # Check if text contains a scan ID
            for sid in pending_scans:
                if sid in (text or "").upper():
                    _matched_id = sid
                    break
        # Or a followup phrase (use most recent scan)
        if not _matched_id and any(ph in _text_lower_check for ph in _video_followup_phrases):
            _matched_id = sorted(pending_scans.keys(),
                                 key=lambda k: pending_scans[k]["timestamp"],
                                 reverse=True)[0]

        if _matched_id:
            scan_info = pending_scans[_matched_id]
            status = scan_info.get("status", "processing")
            if status == "processing":
                return (
                    f"⏳ *Still Processing* — Scan `{_matched_id}`\n\n"
                    f"Your video is still being analysed. Please check back in a few seconds."
                )
            elif status == "error":
                # Clean up
                del pending_scans[_matched_id]
                await update_session(phone, _pending_video_scans=pending_scans)
                return f"❌ Video analysis failed: {scan_info.get('error_msg','Unknown error')}. Please resend the video."
            elif status == "no_face":
                del pending_scans[_matched_id]
                await update_session(phone, _pending_video_scans=pending_scans)
                return (
                    "👤 *No Face Detected*\n\n"
                    "I couldn't find a human face in the video.\n\n"
                    "Verdict: Cannot analyse.\n"
                    "Action: Please send a video with a clear, visible face for deepfake detection."
                )
            elif status == "done":
                result = scan_info["result"]
                del pending_scans[_matched_id]
                await update_session(phone, _pending_video_scans=pending_scans)
                human_exp = await explain_result(
                    "deepfake", result.get("overall_risk_level", ""),
                    result, user_question=scan_info.get("text") or "Is this video a deepfake?"
                )
                reply = format_deepfake_video(result, human_explanation=human_exp or "")
                await store_last_scan(phone, "deepfake", result,
                                      result.get("overall_risk_level",""), result.get("all_flags",[]),
                                      original_input="[video]", item_scanned="video")
                return f"✅ *Scan `{_matched_id}` Complete*\n\n" + reply

    # FIX: When an actual image is present, override followup routing →
    # image analysis always takes priority over last_scan context
    if image_b64 and ent.has_image:
        _img_text = (text or "").lower()
        _explicit_prior = any(kw in _img_text for kw in {
            "the last", "previous result", "the result", "what you found",
            "what did you say", "your previous", "you said",
        })
        if not _explicit_prior:
            decision = classify(text or "", ent, {"state": "IDLE", "last_scan": None})
        else:
            decision = classify(text or "", ent, session)
    else:
        decision = classify(text or "", ent, session)

    # Log user turn (BUG-003: only once)
    await append_history(phone, "user", text or f"[{media_type}]", module="")

    # Dispatch
    reply = await _dispatch(phone, decision, session, image_b64)
    if reply is None:
        reply = "⚠️ An unexpected error occurred. Please try again."

    # Log bot turn (BUG-003: only once — removed duplicate)
    await append_history(phone, "bot", reply[:300], module=str(decision.primary))

    return reply


async def _dispatch(
    phone: str,
    decision: RouteDecision,
    session: dict,
    image_b64: Optional[str],
) -> str:
    # Reset disambiguation state if user sent something new
    if (session.get("state") == "AWAITING_DISAMBIGUATION"
            and decision.primary != Module.SPECIAL
            and decision.action not in ("disambiguate_retry", "disambiguate", "disambiguate_credential_type")):
        await update_session(phone, state=ConvState.IDLE,
                             disambiguation_options={}, pending_entities=[])
        session = await get_or_create_session(phone)

    p = decision.primary

    # ── SPECIAL states ────────────────────────────────────────────────────────
    if p == Module.SPECIAL:
        return await _handle_special(phone, decision, session, image_b64)

    # ── IRRELEVANT ────────────────────────────────────────────────────────────
    if p == Module.IRRELEVANT:
        action = decision.action
        if action == "no_voice":
            return fmt.format_irrelevant("no_voice")
        if action == "urdu_message":
            urdu_result = await classify_urdu(decision.raw_text)
            intent    = urdu_result.get("intent", "offtopic")
            extracted = urdu_result.get("extracted", "")
            english_q = urdu_result.get("english_summary", decision.raw_text)

            # FIX-005: Detect language to reply in same language
            _is_urdu_script = bool(re.search(
                r"[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]",
                decision.raw_text
            ))
            _reply_lang = "Urdu" if _is_urdu_script else "Roman Urdu (using Pakistani everyday words)"

            if intent == "url" and extracted:
                ent2  = extract(extracted)
                new_d = RouteDecision(primary=Module.LINK, action="scan", entities=ent2, raw_text=extracted)
                eng_reply = await _handle_link(phone, new_d, session)
                # Translate back to user's language via Ollama
                translated = await _translate_reply(eng_reply, _reply_lang, decision.raw_text)
                return translated or eng_reply

            if intent == "credential" and extracted:
                ent2  = extract(extracted)
                new_d = RouteDecision(primary=Module.CREDENTIAL, action="detect_and_analyze", entities=ent2, raw_text=extracted)
                eng_reply = await _handle_credential(phone, new_d, session)
                translated = await _translate_reply(eng_reply, _reply_lang, decision.raw_text)
                return translated or eng_reply

            if intent == "profile" and extracted:
                ent2  = extract(extracted)
                new_d = RouteDecision(primary=Module.PROFILE, action="analyze", entities=ent2, raw_text=extracted)
                eng_reply = await _handle_profile(phone, new_d, session)
                translated = await _translate_reply(eng_reply, _reply_lang, decision.raw_text)
                return translated or eng_reply

            if intent == "cyber_qa":
                prompt = (
                    f"The user asked in {_reply_lang}: \"{decision.raw_text}\"\n"
                    f"Their question is about: {english_q}\n\n"
                    f"Answer in {_reply_lang} using simple, everyday Pakistani words. "
                    f"Keep it to 3-4 sentences. End with one concrete action."
                )
                ans = await _ask_ollama(prompt)
                return ans or fmt.format_irrelevant("urdu_message")

            # Generic Urdu/Roman Urdu response
            prompt = (
                f"User sent this message in {_reply_lang}: \"{decision.raw_text}\"\n\n"
                f"You are Aegis AI, a cybersecurity WhatsApp bot. "
                f"Reply in {_reply_lang}. Tell the user you can help with: "
                f"links check (links ki safety), QR codes scan karna, "
                f"credentials check (email/password/CNIC), "
                f"aur social profiles verify karna. "
                f"Ask them to share what they want to check. Keep it friendly and short."
            )
            urdu_reply = await _ask_ollama(prompt)
            return urdu_reply or fmt.format_irrelevant("urdu_message")
        if action == "emoji_only":
            return fmt.format_irrelevant("emoji_only")
        if action == "gibberish":
            return fmt.format_irrelevant("gibberish")
        if action == "angry_user":
            return fmt.format_irrelevant("angry_user")
        if action == "off_topic":
            # ENH-004: detect if user is sending a mismatched input type
            mismatch = _detect_mismatch(decision.raw_text, session)
            if mismatch:
                return mismatch
            user_msg = (decision.raw_text or "")[:120]
            prompt = (
                f"User sent to Aegis AI (cybersecurity WhatsApp bot): '{user_msg}'\n"
                f"This is NOT a cybersecurity question. Write ONE warm, polite sentence "
                f"explaining you only help with: checking links, QR codes, credentials, and "
                f"fake profiles. Do not be robotic. Be friendly and brief. No bullet points."
            )
            off_msg = await _ask_ollama(prompt)
            if off_msg and len(off_msg) > 10:
                return off_msg + "\n\nSend /help to see what I can check for you."
            return fmt.format_irrelevant("off_topic")
        if action in ("bot_who", "who_are_you"):
            # ENH-008: unique intro via Ollama
            user_q = decision.raw_text or "who are you"
            aegis_context = (
                "You are Aegis AI, a cybersecurity WhatsApp assistant built as a "
                "Final Year Project at Lahore Garrison University by Azka Shaukat (2025-2026). "
                "You analyse: URLs for phishing/malware, QR codes for threats, "
                "credentials (email/password/CNIC/card/API keys) for data breaches, "
                "and social media profiles for fake/bot/scammer detection. "
                "You use Ollama (Llama3.2) for plain English explanations. "
                "You protect Pakistani users from JazzCash/HBL/NADRA scams and cyber fraud."
            )
            prompt = (
                f"The user asked: '{user_q}'.\n"
                f"Context: {aegis_context}\n\n"
                "Write a warm, friendly 3-4 sentence introduction. Mention key capabilities. "
                "Every response should feel fresh — vary your phrasing each time."
            )
            intro = await _ask_ollama(prompt)
            if intro and len(intro) > 20:
                return intro
            return fmt.format_irrelevant("bot_who")
        if action == "jailbreak_block":
            return fmt.format_irrelevant("jailbreak_block")
        return fmt.format_irrelevant("off_topic")

    # ── CYBER Q&A — ENH-005: always different via answer_cyber_qa ────────────
    if p == Module.CYBER_QA:
        ans = await answer_cyber_qa(decision.raw_text)
        if ans:
            return ans
        qa_response = fmt.format_cyber_qa(decision.raw_text)
        if qa_response:
            return qa_response
        return _static_cyber_answer(decision.raw_text)

    # ── LINK ──────────────────────────────────────────────────────────────────
    if p == Module.LINK:
        return await _handle_link(phone, decision, session)

    # ── QR ────────────────────────────────────────────────────────────────────
    if p == Module.QR:
        return await _handle_qr(phone, decision, session, image_b64)

    # ── DEEPFAKE ──────────────────────────────────────────────────────────────
    if p == Module.DEEPFAKE:
        return await _handle_deepfake(phone, decision, session, image_b64)

    # ── CREDENTIAL ────────────────────────────────────────────────────────────
    if p == Module.CREDENTIAL:
        return await _handle_credential(phone, decision, session)

    # ── PROFILE ───────────────────────────────────────────────────────────────
    if p == Module.PROFILE:
        return await _handle_profile(phone, decision, session)

    # ── MULTI — ENH-006: confirmed parallel via asyncio.gather ───────────────
    if p == Module.MULTI:
        return await _handle_multi(phone, decision, session, image_b64)

    # ── FOLLOW-UP ─────────────────────────────────────────────────────────────
    if p == Module.FOLLOWUP:
        return await _handle_followup(phone, decision, session)

    # ── Fallback follow-up check ──────────────────────────────────────────────
    # BUG-006: load last_scan / last_module from session (they were undefined before)
    _last_scan   = session.get("last_scan") or {}
    _last_module = session.get("last_module", "scan")
    if _last_scan and not decision.entities:
        raw_lower = (decision.raw_text or "").lower()
        from app.router.intent import _FOLLOWUP_RESCAN, _FOLLOWUP_EXPLAIN, _FOLLOWUP_ACTION
        if any(kw in raw_lower for kw in _FOLLOWUP_RESCAN):
            fol_d = RouteDecision(primary=Module.FOLLOWUP, action="rescan", raw_text=decision.raw_text, context=decision.raw_text)
            return await _handle_followup(phone, fol_d, session)
        if any(kw in raw_lower for kw in _FOLLOWUP_EXPLAIN):
            fol_d = RouteDecision(primary=Module.FOLLOWUP, action="explain", raw_text=decision.raw_text, context=decision.raw_text)
            return await _handle_followup(phone, fol_d, session)
        if any(kw in raw_lower for kw in _FOLLOWUP_ACTION):
            fol_d = RouteDecision(primary=Module.FOLLOWUP, action="action_advice", raw_text=decision.raw_text, context=decision.raw_text)
            return await _handle_followup(phone, fol_d, session)

    # Multi-line question fallback using Ollama
    raw = decision.raw_text or ""
    lines = [l.strip() for l in re.split(r"[\n?]", raw) if l.strip() and len(l.strip()) > 3]
    if len(lines) > 1 and _last_scan:
        combined_q = "\n".join(lines)
        ctx = (
            f"Last scan: {_last_module}, "
            f"Risk: {_last_scan.get('risk_level','')}, "
            f"Item: {_last_scan.get('item_scanned','')}"
        )
        prompt = (
            f"Context: {ctx}\n\n"
            f"User has multiple questions:\n{combined_q}\n\n"
            f"Answer each question briefly. 3-5 sentences total."
        )
        multi_reply = await _ask_ollama(prompt)
        if multi_reply:
            return multi_reply

    return fmt.format_error("Unrecognised route.")


# ENH-004 / FIX-7: Cross-type mismatch detection
def _detect_mismatch(raw_text: str, session: dict) -> Optional[str]:
    """
    FIX-7: Detect wrong X — user says 'scan this link' but sends a CNIC, etc.
    Returns a polite redirect message, or None if no mismatch.
    """
    from app.router.extractor import extract as _ext
    t     = (raw_text or "").lower()
    state = session.get("state", "IDLE")
    ent   = _ext(raw_text or "")

    # ── State-based mismatches ──────────────────────────────────────────────
    if state == "AWAITING_CREDENTIAL":
        if ent.urls or ent.social_urls:
            return (
                "🔗 That looks like a *link*, not a credential.\n\n"
                "I'm currently waiting for a credential (email, password, CNIC, etc.).\n"
                "Please send the credential you want to check, or type /cancel to start over."
            )

    if state == "AWAITING_LINK_OFFER":
        if re.search(r'\d{5}-\d{7}-\d', raw_text):
            return (
                "🪪 That looks like a *CNIC number*.\n\n"
                "I'm waiting to know if you want a profile analysis of the social link.\n"
                "Reply *YES* to run profile analysis, or send your CNIC in a new message."
            )

    # ── Text content mismatches ─────────────────────────────────────────────
    _wants_link = any(kw in t for kw in {
        "scan this link","scan this url","check this link","check this url",
        "is this link safe","is this url safe","is this website safe",
    })
    if _wants_link:
        if ent.emails and not ent.urls:
            return ("📧 That's an *email address*, not a link.\n\n"
                    "• To scan a link → send the URL (e.g. `https://example.com`)\n"
                    "• To check if this email was breached → just send the email address")
        if ent.cnics and not ent.urls:
            return ("🪪 That's a *CNIC number*, not a link.\n\n"
                    "• To scan a link → send the URL\n"
                    "• To check this CNIC → just send the CNIC number")
        if ent.phone_numbers and not ent.urls:
            return ("📱 That's a *phone number*, not a link.\n\n"
                    "• To scan a link → send the URL\n"
                    "• To check this phone number → just send the number")
        if ent.passwords and not ent.urls:
            return ("🔐 That looks like a *password*, not a link.\n\n"
                    "• To scan a link → send the URL\n"
                    "• To check this password → just send it and I'll analyse it")

    _wants_email = any(kw in t for kw in {
        "check this email","is this email","check email","check my email",
        "email breach","is this email breached","email hacked",
    })
    if _wants_email:
        if ent.urls and not ent.emails:
            return ("🔗 That's a *link*, not an email.\n\n"
                    "• To check an email → send the email address (e.g. `test@gmail.com`)\n"
                    "• To scan this link for safety → I can do that too, just confirm")
        if ent.cnics and not ent.emails:
            return ("🪪 That's a *CNIC*, not an email address.\n\n"
                    "Please send the email address you want to check (e.g. `test@gmail.com`)")
        if ent.phone_numbers and not ent.emails:
            return ("📱 That's a *phone number*, not an email.\n\n"
                    "• To check an email → send the email address\n"
                    "• To check this phone number → I can do that too")

    _wants_pwd = any(kw in t for kw in {
        "check my password","check this password","is this password",
        "password check","is my password","test my password",
    })
    if _wants_pwd and ent.emails and not ent.passwords:
        return ("📧 That's an *email address*, not a password.\n\n"
                "• To check the email for breaches → just send the email\n"
                "• To check a password → send just the password text")

    _wants_qr = any(kw in t for kw in {
        "scan this qr","scan qr","check this qr","qr code check","qr scan","check qr",
    })
    if _wants_qr and (ent.urls or ent.emails or ent.cnics):
        return ("📷 You asked to scan a *QR code*, but you sent text.\n\n"
                "Please send a *QR code image* — take a screenshot of the QR code "
                "and send it here directly.")

    _wants_profile = any(kw in t for kw in {
        "check this profile","is this account real","check profile","profile check",
    })
    if _wants_profile and ent.emails and not ent.handles:
        username_part = ent.emails[0].split("@")[0]
        return (f"📧 I found an *email*, not a social profile handle.\n\n"
                f"• Check `{ent.emails[0]}` for breaches → just send it\n"
                f"• Check `@{username_part}` as a social profile → send `@{username_part}`")

    return None


# ══════════════════════════════════════════════════════════════════════════════
# LINK HANDLER
# ══════════════════════════════════════════════════════════════════════════════

async def _handle_link(phone: str, decision: RouteDecision, session: dict) -> str:
    ent    = decision.entities if decision.entities is not None else extract(decision.raw_text or "")
    action = decision.action

    if action == "async_status":
        job_id = decision.raw_text.replace("/status", "").strip().split()[0] if decision.raw_text else ""
        if not job_id:
            return "Please provide a Job ID: `/status <job_id>`"
        result = await api.link_async_status(job_id)
        if result.get("status") == "complete":
            r = result.get("result", {})
            url = r.get("url", "")
            reply = fmt.format_link_async_complete(url, r)
            await store_last_scan(phone, "link", r, r.get("risk_level", ""), r.get("all_flags", []))
            return reply
        if result.get("status") == "pending":
            return f"⏳ Scan still running... try again in a few seconds.\nJob: `{job_id[:8]}`"
        return fmt.format_error(result.get("error", "Job not found."))

    if action == "scan" and decision.command == "/scan" and "async" in (decision.raw_text or "").lower():
        urls = ent.urls or ([u["url"] for u in ent.social_urls] if ent.social_urls else [])
        if not urls:
            return "Please provide a URL: `/scan async https://example.com`"
        result = await api.link_async_submit(urls[0])
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Link Analyzer")
        job_id = result.get("job_id", "")
        return fmt.format_link_async_submitted(job_id, urls[0])

    if action == "social_url_dual" and ent.social_urls:
        su = ent.social_urls[0]
        url_to_scan = su["url"]
        try:
            result = await api.link_scan(url_to_scan)
        except Exception as e:
            logger.error(f"link_scan API error: {e}")
            return "❌ Could not scan the link. Please check if the URL is valid and try again."

        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Link Analyzer")
        if result.get("status") == "error":
            error_msg = result.get("message", result.get("error", "Unknown error"))
            return f"❌ Could not scan the link: {error_msg[:100]}"

        if "risk_level" not in result:
            result["risk_level"] = result.get("overall_risk_level", "Unknown")

        await store_last_scan(phone, "link", result, result.get("risk_level", ""), result.get("all_flags", []))
        human_exp = await explain_result("link", result.get("risk_level", ""), result)
        link_reply = fmt.format_link_scan(su["url"], result, human_explanation=human_exp or "")
        screenshot = result.get("screenshot_url", "")
        if screenshot:
            link_reply += f"\n\n__SCREENSHOT__{screenshot}__SCREENSHOT__"

        await update_session(
            phone,
            state=ConvState.AWAITING_LINK_OFFER,
            _pending_social_handle=su["handle"],
            _pending_social_platform=su["platform"],
        )
        profile_offer = (
            f"\n\n👤 This is a social media profile URL.\n"
            f"Want me to also analyse *@{su['handle']}* for fake account / bot signals?\n"
            f"Reply *YES* to run a profile analysis."
        )
        return link_reply + profile_offer

    if action == "from_social_url":
        handle_info = session.get("_pending_social_handle", "")
        platform    = session.get("_pending_social_platform", "")
        if not handle_info:
            return fmt.format_error("Context lost. Please resend the profile URL.")
        profile_data = {"username": handle_info, "claimed_platform": platform}
        result = await api.profile_analyze(profile_data)
        await update_session(phone, state=ConvState.IDLE)
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Profile Analyzer")
        await store_last_scan(phone, "profile", result,
                              result.get("verdict", {}).get("risk_level", ""),
                              result.get("verdict", {}).get("top_flags", []),
                              original_input=decision.raw_text, item_scanned=handle_info)
        return fmt.format_profile_result(handle_info, result)

    if action == "bulk_scan":
        all_urls = ent.urls + ([u["url"] for u in ent.social_urls] if ent.social_urls else [])
        if len(all_urls) > 10:
            all_urls = all_urls[:10]
        result = await api.link_bulk_scan(all_urls)
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Link Analyzer")
        results_list = result.get("results", [])
        if not results_list:
            return fmt.format_error("Bulk scan returned no results.")
        await store_last_scan(phone, "link", result, result.get("highest_risk_level", ""), [],
                              original_input=decision.raw_text, item_scanned=decision.raw_text.strip())
        bulk_summary = f"Scanned {len(results_list)} URLs. Highest risk: {result.get('highest_risk_level', 'Unknown')}"
        human_exp = await explain_result("link_bulk", result.get("highest_risk_level", ""), {"summary": bulk_summary},
                                         user_question=decision.context or decision.raw_text)
        return fmt.format_link_bulk(results_list, user_context=decision.context or decision.raw_text, human_explanation=human_exp or "")

    # Single scan
    urls = ent.urls or ([u["url"] for u in ent.social_urls] if ent.social_urls else [])
    if not urls:
        raw = (decision.raw_text or "").strip()
        if raw:
            return fmt.format_link_domain_disambig(raw)
        return "🔗 Please send the link (URL) you want me to scan."

    try:
        result = await api.link_scan(urls[0])
    except Exception as e:
        logger.error("link_scan API error: %s", e)
        return fmt.format_module_unavailable("Link Analyzer")

    if not result or result.get("module_unavailable"):
        return fmt.format_module_unavailable("Link Analyzer")

    if result.get("status") == "error":
        error_msg = result.get("message", result.get("error", "Unknown error"))
        return f"❌ Could not scan the link: {error_msg[:100]}"

    if "risk_level" not in result:
        result["risk_level"] = result.get("overall_risk_level", "Unknown")

    try:
        await store_last_scan(phone, "link", result, result.get("risk_level", ""), result.get("all_flags", []),
                              original_input=decision.raw_text, item_scanned=urls[0] if urls else "")
    except Exception as e:
        logger.warning("store_last_scan error: %s", e)

    await update_session(phone, state=ConvState.IDLE)

    try:
        human_exp = await explain_result("link", result.get("risk_level", ""), result,
                                         user_question=decision.context or decision.raw_text)
    except Exception as e:
        logger.warning("explain_result error: %s", e)
        human_exp = ""

    base_reply = fmt.format_link_scan(urls[0], result, human_explanation=human_exp or "")

    raw_lower = (decision.raw_text or "").lower()
    if any(kw in raw_lower for kw in ["my boss", "sent this", "is it safe", "check this"]):
        base_reply = f"⚠️ I found a link in your message and scanned it:\n`{urls[0]}`\n\n" + base_reply

    if len(urls) == 1 and _is_image_url(urls[0]):
        base_reply += (
            "\n\n🖼️ *Image Detected*\n"
            "Would you like to run deepfake analysis on this image?\n"
            "Reply *YES* to analyse."
        )
        await update_session(phone, _pending_image_url=urls[0], state=ConvState.AWAITING_DEEPFAKE_CONFIRM)

    screenshot = result.get("screenshot_url", "")
    if screenshot:
        base_reply += f"\n\n__SCREENSHOT__{screenshot}__SCREENSHOT__"

    return base_reply


# ══════════════════════════════════════════════════════════════════════════════
# QR HANDLER
# ══════════════════════════════════════════════════════════════════════════════

def _normalize_single_qr(qr: dict) -> dict:
    normalized = {}
    normalized["qr_type"]        = qr.get("qr_type", "unknown")
    normalized["decoded_payload"] = qr.get("deobfuscation", {}).get("likely_true_payload", "")
    normalized["overall_risk"]   = qr.get("final_risk_level", "Safe")
    normalized["risk_score"]     = qr.get("final_risk_score", 0)

    flags = []
    deobf = qr.get("deobfuscation", {})
    if deobf.get("critical_alert"):
        flags.append(deobf["critical_alert"])
    type_analysis = qr.get("type_analysis", {})
    if type_analysis.get("flags"):
        flags.extend(type_analysis["flags"])
    parsed = qr.get("parsed_content", {})
    if parsed.get("flags"):
        flags.extend(parsed["flags"])
    smish = qr.get("smishing_analysis", {})
    if smish.get("patterns_matched"):
        flags.append(f"Smishing score: {smish.get('smishing_score', 0)}")
    url_scans = qr.get("url_deep_scans", [])
    for url_scan in url_scans:
        if url_scan.get("all_flags"):
            flags.extend(url_scan["all_flags"])
        if url_scan.get("risk_level"):
            flags.append(f"Linked URL: {url_scan['risk_level']}")

    normalized["all_flags"] = list(dict.fromkeys(flags))
    if url_scans:
        normalized["link_scan"] = url_scans[0]
    if normalized["qr_type"] == "email":
        normalized["email_data"] = parsed
    elif normalized["qr_type"] == "wifi":
        normalized["wifi"] = type_analysis
    return normalized


async def _detect_qr_or_face(image_b64: str) -> tuple[str, Optional[dict]]:
    try:
        qr_result = await api.qr_scan_base64(image_b64)
        if qr_result.get("module_unavailable"):
            raise Exception("QR service unavailable")
        total = qr_result.get("total_qr_found", 0)
        if total > 0:
            if total > 1:
                multiple = [_normalize_single_qr(a) for a in qr_result.get("analyses", [])]
                return ("multi_qr", multiple)
            else:
                analysis  = qr_result["analyses"][0]
                normalized = _normalize_single_qr(analysis)
                return ("qr", normalized)
    except Exception as e:
        logger.debug("QR detection error: %s", e)

    try:
        import base64
        img_bytes = base64.b64decode(image_b64)
        df_result = await analyze_image_bytes(img_bytes)
        if not df_result.get("module_unavailable"):
            face_info = df_result.get("face_info", {})
            if face_info.get("faces_detected", 0) > 0:
                return ("deepfake", df_result)
    except Exception as e:
        logger.debug("Deepfake call error: %s", e)

    return ("none", None)


async def _process_qr_result(phone: str, result: dict, session: dict, decision: RouteDecision) -> str:
    try:
        risk_for_exp = result.get("overall_risk", "Safe")
        human_exp = await explain_result("qr", risk_for_exp, result,
                                         user_question=decision.context or decision.raw_text)
        item_scanned = result.get("decoded_payload", "QR Image")[:80]
        await store_last_scan(phone, "qr", result, result.get("overall_risk", ""), result.get("all_flags", []),
                              original_input=decision.raw_text, item_scanned=item_scanned)
        return fmt.format_qr_full(result, human_explanation=human_exp or "")
    except Exception as e:
        logger.error("QR processing error: %s", e, exc_info=True)
        return "❌ Could not process QR code. Please try again with a clearer image."


async def _handle_qr(phone: str, decision: RouteDecision, session: dict, image_b64: Optional[str]) -> str:
    try:
        action = decision.action

        if action == "generate":
            url = (decision.entities.urls[0] if decision.entities and decision.entities.urls
                   else (decision.raw_text or "").replace("/generate", "").strip())
            if not url:
                return "Please provide a URL: `/generate https://yoursite.com`"
            safety = await api.link_scan(url)
            rl = (safety.get("risk_level", "") or "").lower()
            if "high" in rl or "critical" in rl:
                score = safety.get("confidence_score", 0)
                return fmt.format_qr_generate_refused(url, score)
            result = await api.qr_generate(url)
            if result.get("module_unavailable"):
                return fmt.format_module_unavailable("QR Scanner")
            qr_b64 = result.get("qr_base64", "")
            return fmt.format_qr_generated(url, qr_b64)

        if not image_b64:
            return "📷 Please send a QR code image to scan."

        pending_type = session.get("_pending_image_analysis", "auto")
        await update_session(phone, _pending_image_analysis="")
        if not pending_type and session.get("_pending_media_type"):
            pending_type = session.get("_pending_media_type")
            await update_session(phone, _pending_media_type="")
        if not pending_type:
            pending_type = "auto"

        if pending_type == "qr":
            try:
                raw_result = await api.qr_scan_base64(image_b64)
                if not raw_result.get("module_unavailable"):
                    total = raw_result.get("total_qr_found", 0)
                    if total == 0:
                        # FIX: no QR found — try deepfake as fallback, else clear message
                        try:
                            import base64 as _b64
                            img_bytes = _b64.b64decode(image_b64)
                            df_result = await analyze_image_bytes(img_bytes)
                            if not df_result.get("module_unavailable"):
                                face_info = df_result.get("face_info", {})
                                if face_info.get("faces_detected", 0) > 0:
                                    # Face found — run deepfake analysis
                                    return (
                                        "📷 *No QR Code Detected*\n\n"
                                        "I couldn't find a QR code in this image, but I detected a face.\n\n"
                                        + await _handle_deepfake_image(phone, df_result, session, decision)
                                    )
                        except Exception:
                            pass
                        return (
                            "📷 *No QR Code Detected*\n\n"
                            "I couldn't find a QR code in this image.\n\n"
                            "Please send:\n"
                            "• A clear QR code image (make sure the code fills most of the frame)\n"
                            "• Or a face photo if you want deepfake detection"
                        )
                    if total > 1:
                        multiple = [_normalize_single_qr(a) for a in raw_result.get("analyses", [])]
                        return fmt.format_qr_multi(multiple)
                    analysis   = raw_result["analyses"][0]
                    normalized = _normalize_single_qr(analysis)
                    return await _process_qr_result(phone, normalized, session, decision)
                else:
                    return "❌ QR scanner service unavailable. Please try again later."
            except Exception as e:
                logger.error("QR scan error: %s", e, exc_info=True)
                return "❌ Could not scan QR code. Please send a clearer image."

        if pending_type == "deepfake":
            try:
                import base64
                img_bytes = base64.b64decode(image_b64)
                result = await analyze_image_bytes(img_bytes)
                if result.get("module_unavailable"):
                    return fmt.format_module_unavailable("Deepfake Detector")
                return await _handle_deepfake_image(phone, result, session, decision)
            except Exception as e:
                logger.error("Deepfake analysis error: %s", e, exc_info=True)
                return "❌ Could not analyze image. Please try again."

        detection, result = await _detect_qr_or_face(image_b64)
        if detection == "qr":
            return await _process_qr_result(phone, result, session, decision)
        elif detection == "multi_qr":
            return fmt.format_qr_multi(result)
        elif detection == "deepfake":
            return await _handle_deepfake_image(phone, result, session, decision)
        else:
            return (
                "❌ I couldn't detect a QR code or a face in this image.\n\n"
                "Please send:\n"
                "• A clear QR code image\n"
                "• A photo with a visible face for deepfake detection\n"
                "• Or use /help to see what I can do."
            )
    except Exception as e:
        logger.error("QR handler crashed: %s", e, exc_info=True)
        return "❌ QR processing failed. Please try again with a clearer image."


# ══════════════════════════════════════════════════════════════════════════════
# DEEPFAKE HANDLER
# ══════════════════════════════════════════════════════════════════════════════

async def _handle_deepfake(
    phone: str,
    decision: RouteDecision,
    session: dict,
    image_b64: Optional[str],
) -> str:
    action = decision.action

    svc_up = await deepfake_health()
    if not svc_up:
        return (
            "🎭 *Deepfake Detection — Starting Up*\n\n"
            "The deepfake detection service (port 8004) isn't responding.\n"
            "Make sure it is running:\n"
            "`cd deepfake-api && python -m uvicorn app.main:app --port 8004`"
        )

    if action == "analyze_video":
        if not image_b64:
            return (
                "🎬 *Video Deepfake Analysis*\n\n"
                "Please send the video file you want me to check.\n"
                "I support MP4, AVI, and MOV files."
            )
        import base64 as _b64
        try:
            media_bytes = _b64.b64decode(image_b64)
        except Exception:
            return "⚠️ Could not process the video. Please resend it."

        pending_type = session.get("_pending_media_type", "auto")
        if pending_type == "auto":
            pending_type = session.get("_pending_video_analysis", "auto")
        await update_session(phone, _pending_media_type="", _pending_video_analysis="")

        if pending_type == "qr":
            frame_b64 = await _extract_first_frame(media_bytes)
            if frame_b64:
                qr_result = await api.qr_scan_base64(frame_b64)
                if not qr_result.get("module_unavailable") and qr_result.get("qr_count", 0) > 0:
                    fake_decision = RouteDecision(primary=Module.QR, action="scan",
                                                  entities=extract(""), raw_text="[QR detected in video]")
                    return await _handle_qr(phone, fake_decision, session, frame_b64)
            return "❌ No QR code found in this video. Please send a video with a clear QR code."

        result = await analyze_video_bytes(media_bytes)
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Deepfake Detector")
        face_info = result.get("face_info", {})
        if face_info.get("faces_detected", 0) == 0:
            return await _handle_no_face_video(phone, result, decision)
        human_exp = await explain_result("deepfake", result.get("overall_risk_level", ""), result,
                                         user_question=decision.raw_text or "Is this video a deepfake?")
        return format_deepfake_video(result, human_explanation=human_exp or "")

    if action == "analyze_image_url":
        url = decision.context or (decision.raw_text or "").strip()
        if not url:
            return "Please provide the image URL."
        try:
            result = await analyze_image_url(url)
            if result.get("module_unavailable"):
                return fmt.format_module_unavailable("Deepfake Detector")
            face_info = result.get("face_info", {})
            if face_info.get("faces_detected", 0) == 0:
                return await _handle_no_face_image(phone, result, decision)
            human_exp = await explain_result("deepfake", result.get("overall_risk_level", ""), result,
                                             user_question=decision.context or decision.raw_text)
            return format_deepfake_image(result, human_explanation=human_exp or "")
        except Exception as e:
            logger.error(f"Deepfake image URL analysis error: {e}", exc_info=True)
            return "❌ Could not analyze the image URL. The deepfake service may be unreachable."

    if image_b64:
        import base64 as _b64
        try:
            img_bytes = _b64.b64decode(image_b64)
        except Exception:
            return "⚠️ Could not process the image. Please resend it."

        result = await analyze_image_bytes(img_bytes)
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Deepfake Detector")

        face_info = result.get("face_info", {})
        if face_info.get("faces_detected", 0) == 0:
            return await _handle_no_face_image(phone, result, decision)

        human_exp = await explain_result("deepfake", result.get("overall_risk_level", ""), result,
                                         user_question=decision.raw_text or "Is this image a deepfake?")
        reply = format_deepfake_image(result, human_explanation=human_exp or "")

        await store_last_scan(phone, "deepfake", result,
                              result.get("overall_risk_level", ""),
                              result.get("all_flags", []),
                              original_input="[image]", item_scanned="image")
        return reply

    return (
        "🎭 *Deepfake Detection*\n\n"
        "Send me an image or video to check for AI manipulation.\n\n"
        "*What I can detect:*\n"
        "• 🖼️ AI-generated faces (StyleGAN, ProGAN, DALL-E)\n"
        "• 🔄 Face-swapped images\n"
        "• 🎬 Deepfake videos\n"
        "• 📊 GAN artifacts and manipulation traces\n\n"
        "_Just send the image or video directly here._"
    )


# ══════════════════════════════════════════════════════════════════════════════
# CREDENTIAL HANDLER
# ══════════════════════════════════════════════════════════════════════════════

async def _handle_credential(phone: str, decision: RouteDecision, session: dict) -> str:
    ent    = decision.entities if decision.entities is not None else extract(decision.raw_text or "")
    action = decision.action

    if action == "analyze_email":
        emails = ent.emails if ent else []
        if not emails:
            await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
            return "📧 Please send the email address you want to check."
        result = await api.cred_analyze_email(emails[0])
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Credential Analyzer")
        await update_session(phone, state=ConvState.IDLE)
        await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""), result.get("all_flags",[]),
                              original_input=decision.raw_text, item_scanned=emails[0])
        human_exp = await explain_result("credential", result.get("overall_risk_level",""), result)
        return fmt.format_credential_email(emails[0], result, human_explanation=human_exp or "")

    if action == "analyze_password":
        passwords = ent.passwords if ent else []
        if not passwords:
            await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
            return "🔐 Please send the password you want to check.\n\n" + fmt.format_privacy_reminder("password")
        email    = ent.emails[0] if ent.emails else ""
        username = ent.usernames[0] if ent.usernames else ""
        try:
            result = await api.cred_analyze_password(passwords[0], email, username)
        except Exception as e:
            logger.error(f"cred_analyze_password error: {e}")
            return fmt.format_module_unavailable("Credential Analyzer")
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Credential Analyzer")
        await update_session(phone, state=ConvState.IDLE)
        await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""), result.get("all_flags",[]),
                              original_input=decision.raw_text, item_scanned=passwords[0][:3] + "***")
        human_exp = await explain_result("credential", result.get("overall_risk_level",""), result)
        return fmt.format_credential_password(result, human_explanation=human_exp or "")

    if action == "analyze_card":
        cards = ent.cards if ent else []
        if not cards:
            await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
            return "💳 Please send the card number you want to check.\n\n" + fmt.format_privacy_reminder("payment card")
        result = await api.cred_analyze_card(cards[0])
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Credential Analyzer")
        await update_session(phone, state=ConvState.IDLE)
        await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""), result.get("all_flags",[]),
                              original_input=decision.raw_text, item_scanned=decision.raw_text.strip())
        human_exp = await explain_result("credential", result.get("overall_risk_level",""), result)
        return fmt.format_credential_card(result, human_explanation=human_exp or "")

    if action == "analyze_cnic":
        cnics = ent.cnics if ent else []
        if not cnics:
            await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
            return "🪪 Please send the CNIC number (e.g. 35202-1234567-1).\n\n" + fmt.format_privacy_reminder("CNIC")
        raw_cnic = cnics[0]
        digits   = ''.join(filter(str.isdigit, raw_cnic))
        normalized_cnic = digits if len(digits) == 13 else raw_cnic
        try:
            result = await api.cred_analyze_national_id(normalized_cnic, "cnic")
        except Exception as e:
            logger.error(f"cred_analyze_national_id error: {e}", exc_info=True)
            return fmt.format_module_unavailable("Credential Analyzer")
        if result.get("module_unavailable") or result.get("error"):
            return fmt.format_module_unavailable("Credential Analyzer")
        if not result.get("overall_risk_level") and not result.get("overall_risk_score"):
            return fmt.format_error("Could not analyze CNIC. The service may have rejected the format.")
        await update_session(phone, state=ConvState.IDLE)
        await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""), result.get("all_flags",[]),
                              original_input=decision.raw_text, item_scanned=raw_cnic)
        human_exp = await explain_result("credential", result.get("overall_risk_level",""), result,
                                         user_question=decision.context or decision.raw_text)
        return fmt.format_credential_national_id(raw_cnic, result, human_explanation=human_exp or "")

    if action == "analyze_passport":
        mrz_pairs = ent.mrz_pairs if ent else []
        if not mrz_pairs:
            await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
            return "🛂 Please send the Passport MRZ (both lines, one per line).\n\n" + fmt.format_privacy_reminder("passport")
        pair = mrz_pairs[0]
        result = await api.cred_analyze_passport(pair["line1"], pair["line2"])
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Credential Analyzer")
        await update_session(phone, state=ConvState.IDLE)
        await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""), result.get("all_flags",[]),
                              original_input=decision.raw_text, item_scanned=decision.raw_text.strip())
        human_exp = await explain_result("credential", result.get("overall_risk_level",""), result,
                                         user_question=decision.context or decision.raw_text)
        return fmt.format_credential_passport(result, human_explanation=human_exp or "")

    if action == "analyze_iban":
        ibans = ent.ibans if ent else []
        if not ibans:
            await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
            return "🏦 Please send the IBAN (e.g. PK36SCBL0000001123456702)."
        try:
            result = await api.cred_analyze_iban(ibans[0])
        except Exception as e:
            logger.error(f"cred_analyze_iban error: {e}")
            return fmt.format_module_unavailable("Credential Analyzer")
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Credential Analyzer")
        await update_session(phone, state=ConvState.IDLE)
        await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""), result.get("all_flags",[]),
                              original_input=decision.raw_text, item_scanned=ibans[0])
        human_exp = await explain_result("credential", result.get("overall_risk_level",""), result,
                                         user_question=decision.context or decision.raw_text)
        return fmt.format_credential_iban(ibans[0], result, human_explanation=human_exp or "")

    if action == "analyze_crypto":
        addrs = ent.crypto_addresses if ent else []
        if not addrs:
            await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
            return "₿ Please send the crypto wallet address you want to check."
        result = await api.cred_analyze_crypto(addrs[0]["value"])
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Credential Analyzer")
        await update_session(phone, state=ConvState.IDLE)
        await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""), result.get("all_flags",[]),
                              original_input=decision.raw_text, item_scanned=addrs[0]["value"][:20])
        human_exp = await explain_result("credential", result.get("overall_risk_level",""), result,
                                         user_question=decision.context or decision.raw_text)
        return fmt.format_credential_crypto(addrs[0]["value"], result, human_explanation=human_exp or "")

    if action == "analyze_private_key":
        pks = ent.crypto_private_keys if ent else []
        result = {"overall_risk_level": "Critical", "all_flags": [], "crypto": {"is_private_key": True}}
        return fmt.format_credential_crypto(pks[0] if pks else "", result)

    if action == "analyze_phone":
        phones = ent.phone_numbers if ent else []
        if not phones and decision.raw_text:
            ent2 = extract(decision.raw_text.strip())
            phones = ent2.phone_numbers
        if not phones:
            rt = (decision.raw_text or "").strip().lstrip("@")
            if rt.startswith("+") or rt.startswith("0"):
                phones = [rt]
        if not phones:
            await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
            return "📱 Please send the phone number (e.g. +923001234567 or 03001234567)."
        result = await api.cred_analyze_phone(phones[0])
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Credential Analyzer")
        await update_session(phone, state=ConvState.IDLE)
        await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""), result.get("all_flags",[]),
                              original_input=decision.raw_text, item_scanned=phones[0])
        human_exp = await explain_result("credential", result.get("overall_risk_level",""), result)
        return fmt.format_credential_phone(phones[0], result, human_explanation=human_exp or "")

    if action == "analyze_smishing":
        sms_body      = decision.raw_text or decision.context or ""
        phones_in_msg = ent.phone_numbers if ent else []
        urls_in_msg   = ent.urls if ent else []
        analysis = await analyse_smishing(sms_text=sms_body, phone_numbers=phones_in_msg, urls=urls_in_msg)
        risk     = analysis.get("risk_level", "SAFE")

        # Ollama explanation with smishing context
        smishing_facts = (
            f"SMS message: '{sms_body[:200]}'\n"
            f"Risk level: {risk}\n"
            f"Category: {analysis.get('category','unknown')}\n"
            f"Keyword signals: {', '.join(analysis.get('keyword_signals',[])[:5])}\n"
            f"Patterns matched: {len(analysis.get('matched_patterns',[]))}"
        )
        human_exp = await explain_result(
            "smishing", risk, analysis,
            user_question="Is this SMS message a scam or smishing attack?",
            custom_facts=smishing_facts,
        )

        # Build enhanced reply
        base_reply = format_smishing_result(sms_body, analysis)

        if human_exp:
            # Insert Ollama explanation after the header line
            lines = base_reply.split("\n")
            # Find first blank line after header (usually line 2)
            insert_at = 2
            for i, l in enumerate(lines[:5]):
                if l.strip() == "" and i > 0:
                    insert_at = i
                    break
            lines.insert(insert_at, human_exp)
            lines.insert(insert_at + 1, "")
            base_reply = "\n".join(lines)

        await store_last_scan(phone, "credential", {"smishing": True, "sms": sms_body[:100]},
                              risk, analysis.get("keyword_signals", []),
                              original_input=sms_body, item_scanned=sms_body[:60])
        await update_session(phone, state=ConvState.IDLE)
        return base_reply

    if action == "analyze_username":
        username = (decision.raw_text or "").strip().lstrip("@")
        if not username and ent and ent.usernames:
            username = ent.usernames[0]
        if not username:
            await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
            return "👤 Please send the username you want to check."
        result = await api.cred_analyze_username(username)
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Credential Analyzer")
        await update_session(phone, state=ConvState.IDLE)
        await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""), result.get("all_flags",[]),
                              original_input=decision.raw_text, item_scanned=username)
        risk  = result.get("overall_risk_level","Unknown")
        score = result.get("overall_risk_score",0)
        flags = result.get("all_flags",[])
        badge = fmt._risk_badge(risk)
        emoji = fmt._risk_emoji(risk)
        human_exp = await explain_result("credential", risk, result, user_question=decision.context or decision.raw_text)
        lines = [f"{badge} — Username Analysis", f"👤 `{username}`", ""]
        if human_exp: lines += [human_exp, ""]
        lines += [f"⚙️ *Technical Details:*", f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)"]
        for f in flags[:5]: lines.append(f"• {f}")
        return "\n".join(lines)

    if action == "analyze_api_key":
        keys = ent.api_keys if ent else []
        if not keys:
            await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
            return "🔑 Please send the API key or token you want to check."
        result = await api.cred_analyze_api_key(keys[0]["value"])
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Credential Analyzer")
        await update_session(phone, state=ConvState.IDLE)
        await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""), result.get("all_flags",[]),
                              original_input=decision.raw_text, item_scanned=decision.raw_text.strip())
        human_exp = await explain_result("credential", result.get("overall_risk_level",""), result)
        return fmt.format_credential_api_key(result, human_explanation=human_exp or "")

    if action == "bulk_detect":
        items = []
        for e in (ent.emails or []):         items.append({"type":"email","value":e})
        for p in (ent.passwords or []):      items.append({"type":"password","value":p})
        for c in (ent.cards or []):          items.append({"type":"card","value":c})
        for i in (ent.ibans or []):          items.append({"type":"iban","value":i})
        for k in (ent.api_keys or []):       items.append({"type":"api_key","value":k["value"]})
        result = await api.cred_bulk(items)
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Credential Analyzer")
        return fmt.format_credential_bulk(result.get("results", []))

    if action == "detect_and_analyze":
        value = (decision.raw_text or "").strip()
        if not value:
            return fmt.format_error("No credential provided.")
        await update_session(phone, state=ConvState.IDLE, _pending_credential_type="")
        ent2 = extract(value)
        from app.router.intent import _classify_credential as _cc
        cred_d = _cc(ent2, value, value.lower())
        if cred_d and cred_d.action != "detect_and_analyze":
            cred_d.entities = ent2
            cred_d.raw_text = value
            return await _handle_credential(phone, cred_d, {"state": "IDLE"})
        result = await api.cred_detect(value)
        if result.get("module_unavailable"):
            return fmt.format_module_unavailable("Credential Analyzer")
        return fmt.format_credential_detect(result)

    if action.startswith("prompt_for_"):
        cred_type = action.replace("prompt_for_analyze_", "").replace("prompt_for_", "")
        prompts = {
            "email":    "📧 Please send the *email address* you want to check.\nExample: `test@gmail.com`",
            "password": "🔐 Please send the *password* you want to check.\n\n" + fmt.format_privacy_reminder("password"),
            "username": "👤 Please send the *username* you want to check.\nExample: `cryptoking99` or `@username`",
            "card":     "💳 Please send the *card number* you want to check.\n\n" + fmt.format_privacy_reminder("payment card"),
            "iban":     "🏦 Please send the *IBAN* (e.g. `PK36SCBL0000001123456702`).",
            "crypto":   "₿ Please send the *crypto wallet address* you want to check.",
            "cnic":     "🪪 Please send the *CNIC number* (e.g. `35202-1234567-1`).\n\n" + fmt.format_privacy_reminder("CNIC"),
            "passport": "🛂 Please send the *Passport MRZ* (both lines, one per line).\n\n" + fmt.format_privacy_reminder("passport"),
            "phone":    "📱 Please send the *phone number* (e.g. `+923001234567` or `03001234567`).",
            "api_key":  "🔑 Please send the *API key or token* you want to check.",
            "link":     "🔗 Please send the *link (URL)* you want me to scan.",
        }
        await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
        return prompts.get(cred_type, "Please send the credential you want to check.")

    # Fallback: auto-detect
    value = (decision.raw_text or "").strip()
    if value and len(value) > 2:
        result = await api.cred_detect(value)
        if not result.get("module_unavailable"):
            return fmt.format_credential_detect(result)

    return fmt.format_error("Could not determine credential type.")


# ══════════════════════════════════════════════════════════════════════════════
# PROFILE HANDLER
# ══════════════════════════════════════════════════════════════════════════════

async def _handle_profile(phone: str, decision: RouteDecision, session: dict) -> str:
    ent    = decision.entities if decision.entities is not None else extract(decision.raw_text or "")
    action = decision.action

    handle   = ""
    platform = ""
    if ent and ent.handles:
        handle = ent.handles[0]
    elif ent and ent.social_urls:
        su       = ent.social_urls[0]
        handle   = su.get("handle", "")
        platform = su.get("platform", "")
    elif ent and ent.usernames:
        handle = ent.usernames[0]

    if action == "collect_data":
        partial = session.get("partial_profile", {})
        if ent:
            if ent.emails:        partial["email"] = ent.emails[0]
            if ent.phone_numbers: partial["phone"] = ent.phone_numbers[0]
        text = decision.raw_text or ""
        foll_match = re.search(r"follower[s]?\W*(\d[\d,]+)", text, re.I)
        if foll_match:
            partial["followers"] = int(foll_match.group(1).replace(",",""))
        fing_match = re.search(r"following\W*(\d[\d,]+)", text, re.I)
        if fing_match:
            partial["following"] = int(fing_match.group(1).replace(",",""))
        age_match = re.search(r"(\d+)\s*days?\s*old", text, re.I)
        if age_match:
            partial["account_age_days"] = int(age_match.group(1))
        await update_session(phone, partial_profile=partial)
        username = partial.get("username", handle)
        if username and len(partial) >= 2:
            profile_data = {**partial, "username": username}
            result = await api.profile_analyze(profile_data)
            if result.get("module_unavailable"):
                return fmt.format_module_unavailable("Profile Analyzer")
            await update_session(phone, state=ConvState.IDLE, partial_profile={})
            await store_last_scan(phone, "profile", result,
                                  result.get("verdict",{}).get("risk_level",""),
                                  result.get("verdict",{}).get("top_flags",[]),
                                  original_input=decision.raw_text, item_scanned=username)
            return fmt.format_profile_result(username, result)
        return fmt.format_profile_collect_prompt([])

    if handle and action in ("analyze", "analyze_handle", "analyze_handle_unified", ""):
        # ENH-006: run BOTH concurrently (confirmed parallel)
        cred_task    = api.cred_analyze_username(handle)
        profile_task = api.profile_analyze({"username": handle, "claimed_platform": platform})
        c_result, p_result = await asyncio.gather(cred_task, profile_task, return_exceptions=True)
        if isinstance(c_result, Exception): c_result = {}
        if isinstance(p_result, Exception): p_result = {}

        if (not p_result or p_result.get("module_unavailable")) and \
           (not c_result or c_result.get("module_unavailable")):
            return fmt.format_module_unavailable("Profile Analyzer")

        from app.services.username_intelligence import score_and_rank
        uv = score_and_rank(handle, c_result or {}, p_result or {})

        human_exp = await explain_result("profile", uv.risk_level, p_result or {},
                                         user_question=decision.context or decision.raw_text)
        if not human_exp:
            human_exp = uv.plain_explanation

        await store_last_scan(phone, "profile", p_result or {}, uv.risk_level, uv.top_signals,
                              original_input=decision.raw_text, item_scanned=handle)
        await store_long_term(phone, "profile", handle, uv.risk_level, uv.final_verdict)
        await update_session(phone, state=ConvState.IDLE)

        badge = fmt._risk_badge(uv.risk_level)
        lines = [
            f"{badge} — 🎯 Profile Intelligence",
            f"👤 @{handle}",
            "",
            human_exp,
            "",
            "⚙️ *Technical Details:*",
            f"🏆 Verdict: *{uv.final_verdict}* ({uv.confidence}% confidence)",
            f"🛡️ Risk: {fmt._risk_emoji(uv.risk_level)} {uv.risk_level} ({uv.combined_score}/100)",
        ]
        if uv.top_signals:
            lines.append("\n⚠️ *Signals:*")
            for sig in uv.top_signals[:5]:
                lines.append(f"• {sig}")
        lines += ["", uv.recommended_action]
        return "\n".join(lines)

    if action == "profile" or not handle:
        text = (decision.raw_text or "").replace("/profile", "").strip()
        if text:
            handle = text.split()[0].lstrip("@")
            result = await api.profile_analyze({"username": handle})
            if result.get("module_unavailable"):
                return fmt.format_module_unavailable("Profile Analyzer")
            await store_last_scan(phone, "profile", result,
                                  result.get("verdict",{}).get("risk_level",""),
                                  result.get("verdict",{}).get("top_flags",[]),
                                  original_input=decision.raw_text, item_scanned=handle)
            human_exp = await explain_result("profile", result.get("verdict",{}).get("risk_level",""), result)
            return fmt.format_profile_result(handle, result, human_explanation=human_exp or "")
        else:
            await update_session(phone, state=ConvState.AWAITING_PROFILE_DATA, partial_profile={})
            return fmt.format_profile_collect_prompt([])

    return fmt.format_error("No username or profile data found.")


# ══════════════════════════════════════════════════════════════════════════════
# MULTI-MODULE CONCURRENT HANDLER
# ══════════════════════════════════════════════════════════════════════════════

async def _handle_multi(phone: str, decision: RouteDecision, session: dict, image_b64: Optional[str]) -> str:
    """Run concurrent routes and merge results — ENH-006 confirmed parallel."""
    routes = decision.concurrent_routes
    if not routes:
        return fmt.format_error("No routes in multi-dispatch.")

    tasks   = [_dispatch(phone, r, session, image_b64) for r in routes]
    replies = await asyncio.gather(*tasks, return_exceptions=True)  # true parallel

    parts = []
    for i, reply in enumerate(replies):
        if isinstance(reply, Exception):
            parts.append(f"⚠️ Module {i+1} error: {str(reply)[:80]}")
        else:
            module_name = routes[i].primary.value.title() if i < len(routes) else f"Module {i+1}"
            parts.append(f"━━━ *{module_name} Analysis*\n{reply}")

    return "\n\n".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# SPECIAL / SYSTEM HANDLER
# ══════════════════════════════════════════════════════════════════════════════

async def _handle_special(phone: str, decision: RouteDecision, session: dict, image_b64: Optional[str] = None) -> str:
    action = decision.action

    if action in ("help_menu", "help"):
        return fmt.HELP_MENU

    if action == "urdu_help_menu":
        return fmt.HELP_MENU_URDU

    if action == "prompt_for_link":
        return "🔗 Please send the link (URL) you want me to scan."

    if action == "guided_menu":
        await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
        return fmt.CREDENTIAL_MENU

    if action == "general_menu":
        return fmt.HELP_MENU  # ENH-007: reuse formatted help menu

    # FIX-7: wrong-X denial — context carries the denial message
    if action == "wrong_x_deny":
        return decision.context or fmt.format_irrelevant("off_topic")

    if action == "prompt_for_profile":
        return (
            "👤 *Profile Analysis*\n\n"
            "Please send the @username or social handle you want to check.\n\n"
            "Examples:\n"
            "• `@cryptoking99` — with @ symbol\n"
            "• `cryptoking99` — plain username\n"
            "• `https://instagram.com/user` — full profile URL"
        )

    if action == "prompt_credential":
        await update_session(phone, state=ConvState.AWAITING_CREDENTIAL)
        raw = (decision.raw_text or "").lower()
        if "email" in raw:     return "📧 Please send the email address you want to check."
        if "password" in raw:  return "🔐 Please send the password you want to check."
        if "phone" in raw or "number" in raw: return "📱 Please send the phone number (e.g. +923001234567)."
        if "card" in raw:      return "💳 Please send the card number."
        if "iban" in raw:      return "🏦 Please send the IBAN."
        if "cnic" in raw or "national id" in raw: return "🪪 Please send the CNIC number (e.g. 35202-1234567-1)."
        if "api" in raw or "token" in raw or "key" in raw: return "🔑 Please send the API key or token."
        return "🔑 Please send the credential you'd like to check.\n\n" + fmt.CREDENTIAL_MENU

    if action == "clear_session":
        await delete_session(phone)
        return fmt.format_session_cleared()

    if action == "cancel":
        await update_session(phone, state=ConvState.IDLE, partial_profile={}, pending_entities=[])
        return fmt.format_cancel()

    if action in ("history", "show_history"):
        try:
            raw      = (decision.raw_text or "").lower()
            scan_log = session.get("scan_log", [])
            filter_mod = ""
            if any(w in raw for w in ["link","url","website","links"]):
                filter_mod = "link"
            elif any(w in raw for w in ["qr","qr code","qr codes"]):
                filter_mod = "qr"
            elif any(w in raw for w in ["deepfake","face","video","deepfakes"]):
                filter_mod = "deepfake"
            elif any(w in raw for w in ["profile","account","fake profile","profiles"]):
                filter_mod = "profile"
            elif any(w in raw for w in ["smishing","sms","message","phishing message"]):
                filter_mod = "smishing"
            elif any(w in raw for w in ["credential","password","email","breach","cnic","card","iban","crypto","phone","api key"]):
                filter_mod = "credential"
            return fmt.format_scan_log(scan_log, filter_module=filter_mod)
        except Exception as e:
            logger.error("History error: %s", e, exc_info=True)
            return "📋 *Scan History*\n\nNo scans recorded yet in this session."

    if action in ("disambiguate", "disambiguate_credential_type"):
        try:
            opts   = decision.disambig_opts or {}
            entity = ""
            if decision.entities:
                if decision.entities.emails:          entity = decision.entities.emails[0]
                elif decision.entities.phone_numbers: entity = decision.entities.phone_numbers[0]
                elif decision.entities.usernames:     entity = decision.entities.usernames[0]
            if not entity:
                entity = (decision.raw_text or "").strip()[:40]

            await update_session(
                phone,
                state=ConvState.AWAITING_DISAMBIGUATION,
                disambiguation_options={k: list(v) for k, v in opts.items()},
                _disambig_entity=entity,
            )
            parts = [f"BUTTONS:{entity}"]
            for k, (module, val, desc) in opts.items():
                parts.append(f"{k}:{desc}")
            return "||".join(parts)
        except Exception as e:
            logger.error("Disambiguation handler error: %s", e, exc_info=True)
            return fmt.format_irrelevant("off_topic")

    if action == "disambiguate_retry":
        await update_session(phone, state=ConvState.IDLE, disambiguation_options={}, pending_entities=[])
        ent2 = extract(decision.raw_text or "")
        new_d = classify(decision.raw_text or "", ent2, {"state": "IDLE"})
        if new_d.primary != Module.SPECIAL or new_d.action != "disambiguate_retry":
            return await _dispatch(phone, new_d, {"state": "IDLE"}, image_b64)
        return fmt.HELP_MENU

    if action == "from_disambiguation":
        module_name = decision.context if decision.context in (
            "both_email", "both_phone", "credential_email", "profile_email",
            "credential_phone", "profile_phone"
        ) else decision.primary.value
        raw = (decision.raw_text or "").strip().lstrip("@")
        await update_session(phone, state=ConvState.IDLE)

        if module_name == "link":
            ent2 = extract(raw)
            return await _handle_link(phone, RouteDecision(primary=Module.LINK, action="scan", entities=ent2, raw_text=raw), session)

        if module_name == "profile":
            result = await api.profile_analyze({"username": raw, "claimed_platform": ""})
            if result.get("module_unavailable"):
                return fmt.format_module_unavailable("Profile Analyzer")
            await store_last_scan(phone, "profile", result,
                                  result.get("verdict",{}).get("risk_level",""),
                                  result.get("verdict",{}).get("top_flags",[]),
                                  original_input=decision.raw_text, item_scanned=raw)
            human_exp = await explain_result("profile", result.get("verdict",{}).get("risk_level",""), result)
            return fmt.format_profile_result(raw, result, human_explanation=human_exp or "")

        # FIX-4a: Leak Monitor — checks if email/phone appears in data breaches
        if module_name in ("credential_email", "credential_phone"):
            is_email = "@" in raw and "." in raw
            if is_email:
                result, enrichment = await asyncio.gather(
                    api.cred_analyze_email(raw),
                    api.enrich_email_external(raw),
                    return_exceptions=True,
                )
                if isinstance(result, Exception): result = {}
                if isinstance(enrichment, Exception): enrichment = {}
                if result.get("module_unavailable"):
                    return fmt.format_module_unavailable("Credential Analyzer")
                result.update(enrichment or {})
                await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""),
                                      result.get("all_flags",[]), original_input=raw, item_scanned=raw)
                human_exp = await explain_result("credential_leak", result.get("overall_risk_level",""), result,
                                                 user_question=f"Is {raw} in any data breach?")
                return _format_leak_monitor_email(raw, result, human_exp or "")
            else:
                result, enrichment = await asyncio.gather(
                    api.cred_analyze_phone(raw),
                    api.enrich_phone_external(raw),
                    return_exceptions=True,
                )
                if isinstance(result, Exception): result = {}
                if isinstance(enrichment, Exception): enrichment = {}
                if result.get("module_unavailable"):
                    return fmt.format_module_unavailable("Credential Analyzer")
                result.update(enrichment or {})
                await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""),
                                      result.get("all_flags",[]), original_input=raw, item_scanned=raw)
                human_exp = await explain_result("credential_leak", result.get("overall_risk_level",""), result,
                                                 user_question=f"Is {raw} in any data breach?")
                return _format_leak_monitor_phone(raw, result, human_exp or "")

        # FIX-4b: Scam Check — checks if email/phone is linked to scam/fraud activity
        # Uses credential service advanced phone check + IPQS fraud score
        if module_name in ("profile_email", "profile_phone"):
            is_email = "@" in raw and "." in raw
            if is_email:
                result, enrichment = await asyncio.gather(
                    api.cred_analyze_email(raw),
                    api.enrich_email_external(raw),
                    return_exceptions=True,
                )
                if isinstance(result, Exception): result = {}
                if isinstance(enrichment, Exception): enrichment = {}
                if result.get("module_unavailable"):
                    return fmt.format_module_unavailable("Credential Analyzer")
                result.update(enrichment or {})
            else:
                cred_task = api.cred_analyze_phone_advanced(raw)
                result, enrichment = await asyncio.gather(
                    cred_task, api.enrich_phone_external(raw), return_exceptions=True,
                )
                if isinstance(result, Exception): result = await api.cred_analyze_phone(raw)
                if isinstance(enrichment, Exception): enrichment = {}
                if result.get("module_unavailable"): result = await api.cred_analyze_phone(raw)
                if result.get("module_unavailable"):
                    return fmt.format_module_unavailable("Credential Analyzer")
                result.update(enrichment or {})

            await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""),
                                  result.get("all_flags",[]), original_input=raw, item_scanned=raw)
            human_exp = await explain_result("credential_scam", result.get("overall_risk_level",""), result,
                                             user_question=f"Is {raw} a scammer or linked to fraud?")
            return _format_scam_check(raw, result, human_exp or "", is_email=is_email)

        # FIX-4c: Run Both — calls credential service ONCE, formats as two sections
        if module_name in ("both_email", "both_phone"):
            is_email = "@" in raw and "." in raw
            if is_email:
                result = await api.cred_analyze_email(raw)
            else:
                try:
                    result = await api.cred_analyze_phone_advanced(raw)
                    if result.get("module_unavailable"):
                        result = await api.cred_analyze_phone(raw)
                except Exception:
                    result = await api.cred_analyze_phone(raw)

            if result.get("module_unavailable"):
                return fmt.format_module_unavailable("Credential Analyzer")

            await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""),
                                  result.get("all_flags",[]), original_input=raw, item_scanned=raw)
            await update_session(phone, state=ConvState.IDLE)

            # Build two-section reply from one API call
            entity_icon = "📧" if is_email else "📱"
            risk        = result.get("overall_risk_level","Unknown")
            score       = result.get("overall_risk_score", 0)
            badge       = fmt._risk_badge(risk)
            breach      = result.get("hibp_count", 0) or 0
            all_flags   = result.get("all_flags", [])
            fraud_score = result.get("ipqs_fraud_score") or result.get("fraud_score")
            ph          = result.get("phone", {}) or {}
            line_type   = ph.get("line_type","")
            carrier     = ph.get("carrier","")
            is_voip     = ph.get("is_voip", False)

            human_exp = await explain_result("credential", risk, result,
                                             user_question=f"Combined check for {raw}")

            lines = [
                f"{badge} — 🔍 Full Analysis",
                f"{entity_icon} `{raw}`",
                "",
                human_exp or f"Analysis complete for {raw}.",
                "",
            ]

            # ── Section 1: Leak Monitor ──────────────────────────────────────
            lines.append("━━━ 🔑 *Leak Monitor*")
            if breach > 0:
                lines.append(f"🚨 Found in *{breach:,}* data breach record(s)")
                lines.append("⚠️ Your credentials from this account may be circulating online.")
                lines.append("Action: Change passwords on all accounts using this email/number.")
            else:
                lines.append("✅ Not found in any known data breach databases.")
                lines.append("Your number/email has not been exposed in known hacked databases.")
            # Relevant breach flags
            for f in all_flags:
                if any(w in f.lower() for w in ["breach","leaked","exposed","hibp","dehashed"]):
                    lines.append(f"• {f}")
            lines.append("")

            # ── Section 2: Scam Check ────────────────────────────────────────
            lines.append("━━━ 🕵️ *Scam Check*")
            if fraud_score and fraud_score >= 75:
                lines.append(f"🚨 High fraud score: {fraud_score}/100 — strong scam signals detected.")
                lines.append("⚠️ Do not share personal information with this contact.")
            elif fraud_score and fraud_score >= 40:
                lines.append(f"⚠️ Moderate fraud score: {fraud_score}/100 — exercise caution.")
            else:
                # Check flags for scam-related signals
                scam_flags = [f for f in all_flags if any(
                    w in f.lower() for w in ["scam","fraud","voip","disposable","suspicious","spam","abuse","reported"]
                )]
                if scam_flags:
                    lines.append(f"⚠️ Suspicious signals detected:")
                    for f in scam_flags[:3]:
                        lines.append(f"• {f}")
                else:
                    lines.append("✅ No scam or fraud signals detected for this contact.")

            if is_voip:
                lines.append("📡 VoIP number — harder to trace, higher risk of spoofing.")
            if line_type and line_type.lower() not in ("mobile","cell",""):
                lines.append(f"📱 Line type: {line_type}")
            if carrier:
                lines.append(f"📶 Carrier: {carrier}")

            # Scam-related flags
            for f in all_flags:
                if any(w in f.lower() for w in ["impersonat","bot","fake","disposable","recent_abuse"]):
                    lines.append(f"• {f}")
            lines.append("")
            lines.append(f"🛡️ Overall Risk: {fmt._risk_emoji(risk)} {risk} ({score}/100)")
            return "\n".join(lines)

        # FIX-4c: Run Both — parallel, concatenate results
        if module_name in ("both_email", "both_phone"):
            is_email = "@" in raw and "." in raw
            # Run credential + profile in parallel
            c_task = api.cred_analyze_email(raw) if is_email else api.cred_analyze_phone(raw)
            uname_for = raw.split("@")[0] if is_email else raw
            p_task = api.profile_analyze({"username": uname_for, "claimed_platform": ""})
            c_res, p_res = await asyncio.gather(c_task, p_task, return_exceptions=True)
            if isinstance(c_res, Exception): c_res = {}
            if isinstance(p_res, Exception): p_res = {}

            # Build combined reply — concatenate both sections clearly
            from app.services.username_intelligence import score_and_rank
            combined_verdict = score_and_rank(raw, c_res or {}, p_res or {})
            human_exp = await explain_result("profile", combined_verdict.risk_level, p_res or {},
                                             user_question=decision.context or decision.raw_text)

            badge = fmt._risk_badge(combined_verdict.risk_level)
            entity_icon = "📧" if is_email else "📱"

            # ── Section 1: Overall combined verdict ──
            lines = [
                f"{badge} — 🔍 Combined Analysis",
                f"{entity_icon} `{raw}`",
                "",
                human_exp or combined_verdict.plain_explanation,
                "",
                f"🏆 *Overall Verdict: {combined_verdict.final_verdict}* ({combined_verdict.confidence}% confidence)",
                f"🛡️ Combined Risk: {fmt._risk_emoji(combined_verdict.risk_level)} {combined_verdict.risk_level} ({combined_verdict.combined_score}/100)",
                "",
            ]

            # ── Section 2: Leak Monitor results ──
            lines.append("━━━ 🔑 *Leak Monitor (Credential Check)*")
            if c_res and not c_res.get("module_unavailable"):
                c_risk  = c_res.get("overall_risk_level","Unknown")
                c_score = c_res.get("overall_risk_score",0)
                breach  = c_res.get("hibp_count",0)
                c_flags = c_res.get("all_flags",[])
                lines.append(f"🛡️ Risk: {fmt._risk_emoji(c_risk)} {c_risk} ({c_score}/100)")
                if breach and breach > 0:
                    lines.append(f"🚨 Found in *{breach:,}* data breach records")
                else:
                    lines.append("✅ Not found in known data breach databases")
                for f in c_flags[:3]:
                    lines.append(f"• {f}")
            else:
                lines.append("⚠️ Credential service unavailable")
            lines.append("")

            # ── Section 3: Scam Check results ──
            lines.append("━━━ 🕵️ *Scam Check (Profile Analysis)*")
            if p_res and not p_res.get("module_unavailable"):
                p_verdict = p_res.get("verdict", {})
                p_risk    = p_verdict.get("risk_level","Unknown")
                p_score   = p_verdict.get("final_score",0)
                p_flags   = p_verdict.get("top_flags",[])
                fraud_type = p_verdict.get("fraud_type","")
                lines.append(f"🛡️ Risk: {fmt._risk_emoji(p_risk)} {p_risk} ({p_score}/100)")
                if fraud_type and fraud_type not in ("unknown",""):
                    lines.append(f"🎭 Pattern: {fraud_type.replace('_',' ').title()}")
                for f in p_flags[:3]:
                    lines.append(f"• {str(f).replace('_',' ').title()}")
            else:
                lines.append("⚠️ Profile service unavailable")
            lines.append("")

            # ── Evidence ──
            if combined_verdict.top_signals:
                lines.append("⚠️ *Key Evidence:*")
                for sig in combined_verdict.top_signals[:5]:
                    lines.append(f"• {sig}")
                lines.append("")

            lines.append(combined_verdict.recommended_action)

            await store_last_scan(phone, "credential", c_res or {}, combined_verdict.risk_level,
                                  combined_verdict.top_signals, original_input=raw, item_scanned=raw)
            await update_session(phone, state=ConvState.IDLE)
            return "\n".join(lines)

        if module_name in ("credential", "multi"):
            ent2 = extract(raw)
            if not ent2.has_any() and not ent2.emails and not ent2.cards:
                result = await api.cred_analyze_username(raw)
                if result.get("module_unavailable"):
                    return fmt.format_module_unavailable("Credential Analyzer")
                await update_session(phone, state=ConvState.IDLE)
                await store_last_scan(phone, "credential", result, result.get("overall_risk_level",""),
                                      result.get("all_flags",[]), original_input=raw, item_scanned=raw)
                risk  = result.get("overall_risk_level","Unknown")
                score = result.get("overall_risk_score",0)
                badge = fmt._risk_badge(risk)
                flags = result.get("all_flags",[])
                reply_lines = [f"{badge} — Username Analysis", f"👤 `{raw}`", "",
                               "⚙️ *Details:*",
                               f"🛡️ Risk: {fmt._risk_emoji(risk)} {risk.upper()} ({score}/100)"]
                for fl in flags[:5]: reply_lines.append(f"• {fl}")
                return "\n".join(reply_lines)
            new_d = RouteDecision(primary=Module.CREDENTIAL, action="detect_and_analyze", entities=ent2, raw_text=raw)
            return await _handle_credential(phone, new_d, session)

    if action == "jailbreak_block":
        return fmt.format_irrelevant("jailbreak_block")

    if action == "summary":
        return "📊 Session summary is a Phase 2 feature. Coming soon!"

    # Image/video prompt actions
    if action == "prompt_for_image":
        return "📷 Please send the image you want me to analyze. I can check for QR codes or detect deepfakes."
    if action == "prompt_for_qr_image":
        await update_session(phone, state=ConvState.IDLE, _pending_image_analysis="qr")
        return "📷 Please send the QR code image you want me to scan."
    if action == "prompt_for_deepfake_image":
        await update_session(phone, state=ConvState.IDLE, _pending_image_analysis="deepfake")
        return "🎭 Please send the image you want me to check for deepfake manipulation."
    if action == "prompt_for_any_image":
        await update_session(phone, state=ConvState.IDLE, _pending_image_analysis="auto")
        return "📷 Please send the image you want me to analyze. I'll check for QR codes or deepfakes."
    if action == "prompt_for_qr_video":
        await update_session(phone, state=ConvState.IDLE, _pending_video_analysis="qr")
        return "🎥 Please send the video containing the QR code you want me to scan."
    if action == "prompt_for_deepfake_video":
        await update_session(phone, state=ConvState.IDLE, _pending_video_analysis="deepfake")
        return "🎭 Please send the video you want me to check for deepfake manipulation."
    if action == "prompt_for_deepfake_media":
        await update_session(phone, state=ConvState.IDLE, _pending_deepfake_media=True)
        return "🎭 Please send the image or video you want me to check for deepfake manipulation."

    # FIX-10: face scan accepts both image and video
    if action == "prompt_for_deepfake_image_or_video":
        await update_session(phone, state=ConvState.IDLE, _pending_image_analysis="deepfake",
                             _pending_video_analysis="deepfake")
        return (
            "🎭 *Face / Deepfake Check*\n\n"
            "Please send:\n"
            "• 🖼️ An *image* (photo) — I'll check if the face is AI-generated or real\n"
            "• 🎬 A *video* — I'll check for deepfake manipulation\n\n"
            "_Send the image or video directly in this chat._"
        )
    if action == "prompt_for_any_video":
        await update_session(phone, state=ConvState.IDLE, _pending_media_type="video")
        return "🎥 Please send the video you want me to analyze. I'll check for QR codes or deepfakes."
    if action == "prompt_for_any_media":
        await update_session(phone, state=ConvState.IDLE, _pending_media_type="auto")
        return "📷 Please send the image or video you want me to analyze. I'll check for QR codes or deepfakes."

    # FIX-002: Image + wrong intent — ignore image, redirect politely
    if action == "image_but_wants_link":
        return (
            "🔗 It looks like you want to check a *link*, not an image.\n\n"
            "Please send the URL you want me to scan.\n"
            "Example: `https://suspicious-site.com`\n\n"
            "_If you did want to check the image for QR codes or deepfakes, "
            "send it again without any link-related text._"
        )
    if action == "image_but_wants_credential":
        return (
            "🔑 It looks like you want to check a *credential*, not an image.\n\n"
            "Please send the credential you want to analyse.\n"
            "Examples: `test@gmail.com` · `Admin@123` · `35202-1234567-1`\n\n"
            "_If you did want to scan the image, send it again without credential keywords._"
        )
    if action == "image_but_wants_profile":
        return (
            "👤 It looks like you want to check a *profile*, not an image.\n\n"
            "Please send the @username or social handle you want to check.\n"
            "Example: `@cryptoking99` or `https://instagram.com/user`\n\n"
            "_If you did want to check the image for QR or deepfakes, send it again._"
        )

    return fmt.HELP_MENU


# ══════════════════════════════════════════════════════════════════════════════
# FOLLOW-UP HANDLER — ENH-002: all module types handled
# ══════════════════════════════════════════════════════════════════════════════

async def _handle_followup(phone: str, decision: RouteDecision, session: dict) -> str:
    """Handle follow-up messages about a previous scan result.
    ENH-002: Works for link, QR, credential, profile, deepfake, smishing.
    Uses explain_followup() for varied Ollama responses each time.
    """
    action     = decision.action
    raw_text   = decision.raw_text or ""
    raw_lower  = raw_text.lower()
    last_module = session.get("last_module", "scan")
    last_scan   = session.get("last_scan") or {}

    if not last_scan:
        return (
            "❓ I don't have a recent scan in memory to refer back to.\n\n"
            "Please send me a link, QR code, credential, or profile to analyse first."
        )

    result     = last_scan.get("result", {})
    risk       = last_scan.get("risk_level", "")
    flags      = last_scan.get("flags", [])
    score      = last_scan.get("score", 0)
    item       = last_scan.get("item_scanned", last_scan.get("url", ""))
    module_str = last_module or "scan"

    # Build a scan context summary for Ollama
    scan_context = (
        f"Module: {module_str}\n"
        f"Item scanned: {item[:80]}\n"
        f"Risk level: {risk}\n"
        f"Main flags: {', '.join(flags[:3]) if flags else 'none'}\n"
    )

    # ── RESCAN ────────────────────────────────────────────────────────────────
    if action == "rescan" or any(w in raw_lower for w in {
        "again", "rescan", "re-scan", "recheck", "once more", "scan again",
        "check again", "retry", "run again", "redo", "scan it again"
    }):
        if last_module == "link" and item:
            new_result = await api.link_scan(item)
            if new_result.get("module_unavailable"):
                return fmt.format_module_unavailable("Link Analyzer")
            await store_last_scan(phone, "link", new_result, new_result.get("risk_level",""), new_result.get("all_flags",[]),
                                  original_input=item, item_scanned=item)
            human_exp = await explain_result("link", new_result.get("risk_level",""), new_result)
            return "🔄 *Re-scan complete:*\n\n" + fmt.format_link_scan(item, new_result, human_explanation=human_exp or "")
        if last_module == "profile" and item:
            new_result = await api.profile_analyze({"username": item})
            if new_result.get("module_unavailable"):
                return fmt.format_module_unavailable("Profile Analyzer")
            human_exp = await explain_result("profile", new_result.get("verdict",{}).get("risk_level",""), new_result)
            return "🔄 *Re-scan complete:*\n\n" + fmt.format_profile_result(item, new_result, human_explanation=human_exp or "")
        return (
            f"🔄 To re-run the {module_str} scan, please send the same item again.\n"
            f"I can't re-submit without the original URL or file."
        )

    # ── EXPLAIN — ENH-002: use explain_followup for all modules ──────────────
    if action == "explain" or any(w in raw_lower for w in {
        "explain", "what does", "what are", "tell me more", "more details",
        "breakdown", "elaborate", "what is this", "i don't understand",
        "what are flags", "explain the flags", "what does score mean",
        "what does it mean", "can you explain", "what does this mean",
        "what is the risk", "what is the score", "how was this scored"
    }):
        answer = await explain_followup(raw_text, scan_context)
        if answer:
            return answer
        # Fallback
        risk_word = ("HIGH RISK" if ("high" in risk.lower() or "critical" in risk.lower())
                     else "MEDIUM RISK" if "medium" in risk.lower()
                     else "LOW RISK" if "low" in risk.lower() else "SAFE")
        return (
            f"The {module_str} scan showed *{risk_word}*.\n"
            f"Main warning: {flags[0].replace('_',' ') if flags else 'none detected'}.\n"
            f"Ask me anything specific about the result."
        )

    # ── ACTION ADVICE — ENH-002: specific advice per module ──────────────────
    if action == "action_advice" or any(w in raw_lower for w in {
        "what should i do", "what to do", "what do i do", "is that bad",
        "is this bad", "should i worry", "is it dangerous", "what now",
        "am i safe", "should i be worried", "advice", "recommend",
        "help me", "how bad", "what action", "what next", "i clicked",
        "i already clicked", "what if i clicked"
    }):
        answer = await explain_followup(raw_text, scan_context)
        if answer:
            return answer
        # Fallback per module
        rl = risk.lower()
        if "high" in rl or "critical" in rl:
            module_advice = {
                "link":       "Do NOT click or visit that link. If you already visited it, run an antivirus scan and change any passwords entered on that site.",
                "qr":         "Do NOT scan or follow that QR code. If you already did, check your banking apps for unauthorized transactions.",
                "credential": "Change this password/credential immediately and enable 2FA on any account that uses it.",
                "profile":    "Block and report this account. Do not share any personal information with them.",
                "deepfake":   "This image/video is manipulated. Do not share it or make decisions based on it. Report to the platform.",
            }
            advice = module_advice.get(last_module, "Do NOT interact with this item. Report to FIA Cyber Crime: 0800-55555.")
            return f"⚠️ *High Risk — Immediate Action Required*\n\n{advice}"
        elif "medium" in rl:
            return (
                f"⚠️ The {module_str} showed suspicious signals.\n\n"
                f"Be cautious and verify through official channels before proceeding."
            )
        else:
            return f"✅ The {module_str} is safe. No action required. You can proceed normally."

    # ── "CHECK THIS TOO" ──────────────────────────────────────────────────────
    if any(w in raw_lower for w in {"check this too", "this too", "also check", "scan this too"}):
        ent2 = extract(raw_text)
        if ent2.urls:
            new_d = RouteDecision(primary=Module.LINK, action="scan", entities=ent2, raw_text=raw_text)
            return await _handle_link(phone, new_d, session)
        return "Please send the item you'd like me to check."

    # General follow-up: use Ollama classify_followup then delegate
    last_summary = f"Module: {module_str}, Risk: {risk}, Item: {item[:60]}"
    ollama_intent = await classify_followup(raw_text, last_summary)
    intent = ollama_intent.get("intent", "unrelated")
    if intent == "rescan":
        return await _handle_followup(phone, RouteDecision(primary=Module.FOLLOWUP, action="rescan", raw_text=raw_text), session)
    if intent in ("explain", "ask_more"):
        return await _handle_followup(phone, RouteDecision(primary=Module.FOLLOWUP, action="explain", raw_text=raw_text), session)
    if intent == "action_advice":
        return await _handle_followup(phone, RouteDecision(primary=Module.FOLLOWUP, action="action_advice", raw_text=raw_text), session)

    # Final fallback: generic Ollama answer about the scan
    answer = await explain_followup(raw_text, scan_context)
    if answer:
        return answer

    return (
        f"I can answer questions about the last {module_str} scan.\n\n"
        f"Try asking: *explain the result*, *what should I do?*, or *scan it again*."
    )


# ── Utilities ─────────────────────────────────────────────────────────────────

async def _download_image_b64(media_id: str) -> Optional[str]:
    try:
        from app.whatsapp.client import download_media
        import base64
        raw = await download_media(media_id)
        return base64.b64encode(raw).decode()
    except Exception as e:
        logger.error(f"Image download error: {e}")
        return None


# BUG-004 fixed: correct import path used in handle_cyber_qa_ollama
async def handle_cyber_qa_ollama(text: str, session: dict) -> str:
    """Try Ollama first for cyber Q&A. Falls back to static."""
    result = await answer_cyber_qa(text)  # uses app.router.ollama_client
    if result:
        return result
    return _static_cyber_answer(text)


async def _send_scanning_indicator(phone: str) -> None:
    try:
        from app.whatsapp.client import send_text
        await send_text(phone, "🔍 Scanning...")
    except Exception:
        pass


def _format_leak_monitor_email(email: str, result: dict, human_exp: str) -> str:
    """Format email check as Leak Monitor context — focused on breach exposure."""
    risk    = result.get("overall_risk_level","Unknown")
    score   = result.get("overall_risk_score", 0)
    breach  = result.get("hibp_count", 0) or 0
    flags   = result.get("all_flags", [])
    badge   = fmt._risk_badge(risk)
    emoji   = fmt._risk_emoji(risk)

    lines = [f"{badge} — 🔑 Leak Monitor", f"📧 `{email}`", ""]

    if human_exp:
        lines += [human_exp, ""]
    elif breach > 0:
        lines += [f"This email appeared in *{breach:,}* data breach record(s). "
                  f"Credentials linked to this email may be circulating on the dark web.", ""]
    else:
        lines += ["This email has *not* been found in any known data breach databases. "
                  "Your credentials appear safe from known leaks.", ""]

    lines.append("⚙️ *Technical Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")
    if breach > 0:
        lines.append(f"🚨 *Breached:* Found in *{breach:,}* breach record(s)")
        lines.append("💡 Change passwords on all accounts using this email.")
    else:
        lines.append("✅ *Clean:* Not found in known breach databases")

    is_disposable = result.get("is_disposable", False) or result.get("ml_disposable", False) or result.get("hunter_disposable", False)
    if is_disposable:
        lines.append("⚠️ Disposable/throwaway email — no real identity behind it")
    if result.get("domain_has_mx") is False or result.get("ml_mx_found") is False:
        lines.append("⚠️ No mail server found for this domain")
    if result.get("ml_smtp_check") is False:
        lines.append("⚠️ SMTP check failed — mailbox may not exist")
    if result.get("hunter_organization"):
        lines.append(f"🏢 Organisation: {result['hunter_organization']}")
    if result.get("hunter_webmail"):
        lines.append("📮 Free/webmail provider (Gmail, Yahoo, etc.)")
    if result.get("ml_free"):
        lines.append("📮 Free email provider")
    if result.get("ml_role"):
        lines.append("👥 Role address (e.g. admin@, info@) — not a personal account")
    ipqs = result.get("ipqs_fraud_score")
    if ipqs:
        lines.append(f"🎯 IPQS Fraud Score: {ipqs}/100")
    for f in flags[:3]:
        lines.append(f"• {f}")
    lines.append(f"\n{fmt._PRIVACY_NOTE}")
    return "\n".join(lines)


def _format_leak_monitor_phone(phone_num: str, result: dict, human_exp: str) -> str:
    """Format phone check as Leak Monitor context."""
    risk   = result.get("overall_risk_level","Unknown")
    score  = result.get("overall_risk_score", 0)
    breach = result.get("hibp_count", 0) or 0
    flags  = result.get("all_flags", [])
    badge  = fmt._risk_badge(risk)
    emoji  = fmt._risk_emoji(risk)
    ph     = result.get("phone", {}) or {}

    lines = [f"{badge} — 🔑 Leak Monitor", f"📱 `{phone_num}`", ""]

    if human_exp:
        lines += [human_exp, ""]
    elif breach > 0:
        lines += [f"This phone number appeared in *{breach:,}* data breach record(s). "
                  f"Accounts linked to this number may have been exposed.", ""]
    else:
        lines += ["This phone number has *not* been found in any known data breach databases. "
                  "Your number appears safe from known leaks.", ""]

    lines.append("⚙️ *Technical Details:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")
    if breach > 0:
        lines.append(f"🚨 *Breached:* Found in *{breach:,}* record(s)")
    else:
        lines.append("✅ *Clean:* Not found in known breach databases")

    # Carrier / network from credential service
    carrier = ph.get("carrier","") or result.get("nv_carrier","") or result.get("ab_carrier","")
    country = ph.get("country_code","") or result.get("nv_country_name","") or result.get("ab_country","")
    line_type = ph.get("line_type","") or result.get("nv_line_type","") or result.get("ab_line_type","")
    location = result.get("nv_location","")
    intl_fmt = result.get("nv_international","")

    if carrier:     lines.append(f"📶 Carrier: {carrier}")
    if country:     lines.append(f"🌍 Country: {country}")
    if line_type:   lines.append(f"📱 Line type: {line_type}")
    if location:    lines.append(f"📍 Location: {location}")
    if intl_fmt:    lines.append(f"☎️ International: {intl_fmt}")

    is_voip = ph.get("is_voip", False)
    if is_voip:     lines.append("📡 VoIP number detected")

    for f in flags[:3]:
        lines.append(f"• {f}")
    lines.append(f"\n{fmt._PRIVACY_NOTE}")
    return "\n".join(lines)


def _format_scam_check(identifier: str, result: dict, human_exp: str, is_email: bool = True) -> str:
    """Format credential result as Scam Check context — focused on fraud/scam signals."""
    risk        = result.get("overall_risk_level","Unknown")
    score       = result.get("overall_risk_score", 0)
    flags       = result.get("all_flags", [])
    badge       = fmt._risk_badge(risk)
    emoji       = fmt._risk_emoji(risk)
    fraud_score = result.get("ipqs_fraud_score") or result.get("fraud_score")
    ph          = result.get("phone", {}) or {}
    is_voip     = ph.get("is_voip", False)
    line_type   = ph.get("line_type","")
    carrier     = ph.get("carrier","")
    is_disposable = result.get("is_disposable", False)

    entity_icon = "📧" if is_email else "📱"
    lines = [f"{badge} — 🕵️ Scam Check", f"{entity_icon} `{identifier}`", ""]

    if human_exp:
        lines += [human_exp, ""]

    # Scam verdict based on fraud score + flags
    scam_flags = [f for f in flags if any(
        w in f.lower() for w in ["scam","fraud","voip","disposable","suspicious","spam","abuse","reported","fake"]
    )]
    if fraud_score and fraud_score >= 75:
        lines += [f"🚨 *HIGH FRAUD RISK* — Fraud score: {fraud_score}/100\n"
                  f"This {('email' if is_email else 'number')} shows strong scam/fraud signals. "
                  f"Do NOT share personal information with this contact.", ""]
    elif fraud_score and fraud_score >= 40:
        lines += [f"⚠️ *SUSPICIOUS* — Fraud score: {fraud_score}/100\n"
                  f"Some scam signals detected. Exercise caution.", ""]
    elif scam_flags:
        lines += [f"⚠️ *SUSPICIOUS* — Scam-related signals detected.\n"
                  f"Treat with caution before engaging.", ""]
    else:
        lines += [f"✅ *No scam signals detected.*\n"
                  f"This {('email' if is_email else 'number')} does not appear to be linked to known scam activity.", ""]

    lines.append("⚙️ *Scam Analysis:*")
    lines.append(f"🛡️ Risk: {emoji} {risk.upper()} ({score}/100)")
    if fraud_score is not None:
        lines.append(f"🎯 Fraud Score: {fraud_score}/100")
    if is_voip:
        lines.append("📡 VoIP number — easily spoofed, used by scammers")
    if is_disposable:
        lines.append("🗑️ Disposable email — common scammer tactic")
    if line_type and line_type.lower() not in ("mobile","cell",""):
        lines.append(f"📱 Line type: {line_type}")
    if carrier:
        lines.append(f"📶 Carrier: {carrier}")
    for f in scam_flags[:3]:
        lines.append(f"• {f}")

    # Advice
    lines.append("")
    if fraud_score and fraud_score >= 75 or scam_flags:
        lines.append("🚫 *Recommended:* Do not respond to or trust this contact.")
        lines.append("📋 Report scams: nia.gov.pk / FIA Cyber Crime: 0800-55555")
    else:
        lines.append("✅ Safe to engage, but always be cautious with unknown contacts.")
    return "\n".join(lines)


async def _translate_reply(english_reply: str, target_language: str, original_user_msg: str) -> Optional[str]:
    """
    FIX-005: Translate a scan result summary to the user's language.
    Keeps technical details (URLs, scores, flags) in English — only translates
    the explanation and action sentences.
    """
    if not english_reply or len(english_reply) < 20:
        return None
    # Don't translate if reply is already very short (button prompts etc.)
    # Only translate the human explanation parts, not the full technical report
    # Extract just the first paragraph (the Ollama explanation) for translation
    lines = english_reply.split("\n")
    # Find the explanation lines (before technical details)
    explanation_lines = []
    for line in lines:
        if line.startswith("⚙️") or line.startswith("🛡️") or line.startswith("━"):
            break
        explanation_lines.append(line)
    explanation = "\n".join(explanation_lines).strip()
    if not explanation or len(explanation) < 20:
        return None

    prompt = (
        f"Translate ONLY this security message to {target_language}. "
        f"Keep URLs, scores, and technical terms in English. "
        f"Keep it natural and friendly:\n\n"
        f"{explanation}\n\n"
        f"Output ONLY the translated text, nothing else."
    )
    translated = await _ask_ollama(prompt)  # uses default max_tokens
    if translated and len(translated) > 10:
        # Replace the explanation at the top of the reply
        remaining = english_reply[len("\n".join(explanation_lines)):]
        return translated + remaining
    return None
