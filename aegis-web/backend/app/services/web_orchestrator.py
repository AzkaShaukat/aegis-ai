"""web_orchestrator.py — Full WhatsApp orchestrator logic, adapted for web streaming.

Every handler yields an async generator:
  {"type": "thinking", "content": "...", "step": N}
  {"type": "result",   ...full result dict...}          — final
"""

from __future__ import annotations
import asyncio
import logging
import uuid
import re
from typing import AsyncGenerator, Optional, Dict, Any

from app.core.config import get_settings
from app.router.extractor import extract, ExtractedEntities
from app.router.intent import classify, Module, RouteDecision
from app.formatters import responses as fmt
from app.router.ollama_client import (
    explain_result, explain_followup, answer_cyber_qa,
    classify_followup, classify_urdu
)
from app.services.session import (
    get_or_create_session, update_session, store_last_scan, clear_session
)
from app.services.dispatcher import (
    link_scan, link_bulk_scan, qr_scan_base64, qr_generate,
    cred_analyze_email, cred_analyze_password, cred_analyze_card,
    cred_analyze_national_id, cred_analyze_passport, cred_analyze_iban,
    cred_analyze_crypto, cred_analyze_phone, cred_analyze_phone_advanced,
    cred_analyze_username, cred_analyze_api_key, cred_detect,
    profile_analyze, analyze_image_bytes, analyze_video_bytes, analyze_image_url,
    deepfake_health,
)
# Stubs for services_logic (replace with full WhatsApp copies later)
from app.services_logic.smishing_engine import analyse_smishing, format_smishing_result
from app.services_logic.profile_intelligence import compute_unified_verdict
from app.services_logic.username_intelligence import score_and_rank
from app.services_logic.long_term_memory import store_long_term, get_long_term_summary

settings = get_settings()
logger = logging.getLogger(__name__)

# ── Follow-up chips (mirrors WhatsApp quick replies) ─────────
FOLLOWUPS = {
    "link":       ["🔗 Scan another link", "📧 Check email breach", "🎭 Deepfake check"],
    "qr":         ["🔗 Scan the decoded URL", "📷 Scan another QR", "📧 Check email"],
    "credential": ["🔑 Check another email", "🔗 Check a link", "👤 Profile check"],
    "profile":    ["👤 Check another profile", "📧 Check email breach", "🔗 Scan a link"],
    "deepfake":   ["🎭 Analyse another media", "🔗 Check a link", "📧 Check email"],
    "sms_scam":   ["💬 Check another message", "🔗 Scan any links in it", "📧 Check email"],
    "cyber_qa":   ["🔗 Scan a link", "📧 Check email breach", "🎭 Deepfake check"],
    "greeting":   ["🔗 Scan a link", "📧 Check email breach", "🎭 Deepfake check", "👤 Profile check"],
    "help":       ["🔗 Scan a link", "📧 Check email breach", "🎭 Deepfake check"],
}

# ── Main entry point ──────────────────────────────────────────
async def handle_web_message(
    user_id: str,
    session_id: str,
    message_id: str,
    text: str,
    media_bytes: Optional[bytes] = None,
    media_type: Optional[str] = None,
) -> AsyncGenerator[dict, None]:
    """
    Streaming handler – yields thinking events and one final result.
    Mirrors WhatsApp orchestrator routing exactly.
    """
    # 1. Get session (Redis)
    session = await get_or_create_session(session_id)

    # 2. Extract entities
    ent = extract(text or "", media_type=media_type)
    if media_bytes:
        if media_type == "image":
            ent.has_image = True
        elif media_type == "video":
            ent.has_video = True

    # 3. Classify intent (uses WhatsApp's classifier)
    decision = classify(text or "", ent, session)

    # 4. Dispatch – yields events
    async for ev in _dispatch(user_id, session_id, decision, session, media_bytes, media_type):
        yield ev


# ── Dispatcher ─────────────────────────────────────────────────
async def _dispatch(
    user_id: str,
    sid: str,
    decision: RouteDecision,
    session: dict,
    media_bytes: Optional[bytes],
    media_type: Optional[str],
) -> AsyncGenerator[dict, None]:
    primary = decision.primary

    # Clear disambiguation state if user sent new content
    if session.get("state") in ("AWAITING_DISAMBIGUATION", "AWAITING_CREDENTIAL") and primary != Module.SPECIAL:
        session["state"] = "IDLE"
        session["disambiguation_options"] = {}
        await update_session(sid, **session)

    # ── SPECIAL commands ──────────────────────────────────────
    if primary == Module.SPECIAL:
        yield await _handle_special(sid, decision, session)
        return

    # ── IRRELEVANT ────────────────────────────────────────────
    if primary == Module.IRRELEVANT:
        yield await _handle_irrelevant(sid, decision, session)
        return

    # ── CYBER QA ──────────────────────────────────────────────
    if primary == Module.CYBER_QA:
        yield await _handle_cyber_qa(sid, decision, session)
        return

    # ── LINK ──────────────────────────────────────────────────
    if primary == Module.LINK:
        async for ev in _handle_link(sid, decision, session):
            yield ev
        return

    # ── QR ────────────────────────────────────────────────────
    if primary == Module.QR:
        async for ev in _handle_qr(sid, decision, session, media_bytes):
            yield ev
        return

    # ── DEEPFAKE ──────────────────────────────────────────────
    if primary == Module.DEEPFAKE:
        async for ev in _handle_deepfake(sid, decision, session, media_bytes, media_type):
            yield ev
        return

    # ── CREDENTIAL ────────────────────────────────────────────
    if primary == Module.CREDENTIAL:
        async for ev in _handle_credential(sid, decision, session):
            yield ev
        return

    # ── PROFILE ───────────────────────────────────────────────
    if primary == Module.PROFILE:
        async for ev in _handle_profile(sid, decision, session):
            yield ev
        return

    # ── FOLLOWUP ──────────────────────────────────────────────
    if primary == Module.FOLLOWUP:
        async for ev in _handle_followup(sid, decision, session):
            yield ev
        return

    # ── MULTI ─────────────────────────────────────────────────
    if primary == Module.MULTI:
        async for ev in _handle_multi(sid, decision, session, media_bytes, media_type):
            yield ev
        return

    # Fallback
    yield _error_result(sid, "Unrecognised route.")


# ── Individual handlers ───────────────────────────────────────

async def _handle_link(sid: str, decision: RouteDecision, session: dict) -> AsyncGenerator[dict, None]:
    yield {"type": "thinking", "content": "🔍 Analysing link for threats…", "step": 1}

    # Check for mismatch (wrong X)
    mismatch = _detect_mismatch(decision.raw_text, session)
    if mismatch:
        yield _text_result(sid, mismatch, "help", None)
        return

    urls = decision.entities.urls or [u["url"] for u in decision.entities.social_urls]
    if not urls:
        yield _prompt_result(sid, "🔗 Please send the link (URL) you want me to scan.", "link")
        return

    url = urls[0]
    result = await link_scan(url)
    if not result:
        yield _offline_result(sid, "link")
        return

    risk = result.get("risk_level", "Unknown")
    human_exp = await explain_result("link", risk, result, user_question=decision.raw_text)
    formatted = fmt.format_link_scan(url, result, human_explanation=human_exp or "")
    followups = FOLLOWUPS.get("link", [])

    await store_last_scan(sid, "link", result, risk, result.get("all_flags", []), decision.raw_text, url)
    yield {
        "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
        "module": "link", "risk_level": risk,
        "content": formatted,
        "structured": result,
        "followups": followups,
    }


async def _handle_qr(sid: str, decision: RouteDecision, session: dict, media_bytes: Optional[bytes]) -> AsyncGenerator[dict, None]:
    yield {"type": "thinking", "content": "📷 Processing QR code…", "step": 1}

    if not media_bytes:
        yield _prompt_result(sid, "📷 Please send a QR code image to scan.", "qr")
        return

    import base64
    b64 = base64.b64encode(media_bytes).decode()
    result = await qr_scan_base64(b64)
    if not result:
        # Try deepfake as fallback (WhatsApp behaviour)
        df_result = await analyze_image_bytes(media_bytes)
        if df_result and df_result.get("face_info", {}).get("faces_detected", 0) > 0:
            async for ev in _format_deepfake_result(sid, df_result, decision.raw_text):
                yield ev
            return
        yield _error_result(sid, "No QR code or face detected in this image. Please send a clearer QR code.")
        return

    # Normalize QR result (like WhatsApp)
    normalized = _normalize_qr(result)
    risk = normalized.get("overall_risk", "Safe")
    human_exp = await explain_result("qr", risk, normalized, user_question=decision.raw_text)
    formatted = fmt.format_qr_full(normalized, human_explanation=human_exp or "")
    followups = FOLLOWUPS.get("qr", [])

    await store_last_scan(sid, "qr", normalized, risk, normalized.get("all_flags", []), decision.raw_text, normalized.get("decoded_payload", "")[:60])
    yield {
        "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
        "module": "qr", "risk_level": risk,
        "content": formatted,
        "structured": normalized,
        "followups": followups,
    }


def _normalize_qr(raw: dict) -> dict:
    return {
        "qr_type": raw.get("qr_type", "unknown"),
        "decoded_payload": raw.get("decoded_payload") or raw.get("decoded_url") or raw.get("payload") or "",
        "overall_risk": raw.get("risk_level", "Safe"),
        "risk_score": raw.get("score", 0),
        "all_flags": raw.get("flags", []),
    }


async def _handle_deepfake(sid: str, decision: RouteDecision, session: dict,
                           media_bytes: Optional[bytes], media_type: Optional[str]) -> AsyncGenerator[dict, None]:
    yield {"type": "thinking", "content": "🎭 Running deepfake detection…", "step": 1}

    if not media_bytes:
        yield _prompt_result(sid, "🎭 Please send an image or video to check for deepfake manipulation.", "deepfake")
        return

    if media_type == "video":
        result = await analyze_video_bytes(media_bytes)
    else:
        result = await analyze_image_bytes(media_bytes)

    if not result:
        yield _offline_result(sid, "deepfake")
        return

    async for ev in _format_deepfake_result(sid, result, decision.raw_text):
        yield ev


async def _format_deepfake_result(sid: str, result: dict, user_q: str) -> AsyncGenerator[dict, None]:
    risk = result.get("overall_risk_level", "Unknown")
    human_exp = await explain_result("deepfake", risk, result, user_question=user_q)

    # Use WhatsApp formatter if available, else build manual
    try:
        from app.formatters.responses import format_deepfake_image, format_deepfake_video
        if result.get("is_video"):
            content = format_deepfake_video(result, human_explanation=human_exp or "")
        else:
            content = format_deepfake_image(result, human_explanation=human_exp or "")
    except ImportError:
        # Fallback manual formatting
        verdict = result.get("verdict", "Unknown")
        prob = result.get("ensemble_probability", 0) * 100
        content = (f"**Deepfake Analysis**\n\n"
                   f"Verdict: **{verdict}**\n"
                   f"Risk: **{risk}**\n"
                   f"AI Probability: {prob:.0f}%\n\n"
                   f"{human_exp or ''}\n\n"
                   f"⚙️ **Technical Details:**\n"
                   f"• Risk Level: {risk}\n"
                   f"• Confidence: {prob:.0f}%\n"
                   f"• Flags: {', '.join(result.get('all_flags', []))}")

    followups = FOLLOWUPS.get("deepfake", [])
    await store_last_scan(sid, "deepfake", result, risk, result.get("all_flags", []), user_q, "media")
    yield {
        "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
        "module": "deepfake", "risk_level": risk,
        "content": content,
        "structured": result,
        "followups": followups,
    }


async def _handle_credential(sid: str, decision: RouteDecision, session: dict) -> AsyncGenerator[dict, None]:
    yield {"type": "thinking", "content": "🔑 Checking breach databases…", "step": 1}

    # Handle disambiguation results from special actions
    if decision.action == "from_disambiguation":
        # This is handled in _handle_special; we should not get here.
        pass

    # Check for mismatch (wrong X)
    mismatch = _detect_mismatch(decision.raw_text, session)
    if mismatch:
        yield _text_result(sid, mismatch, "help", None)
        return

    ent = decision.entities
    value = decision.raw_text.strip()

    # Handle email
    if ent.emails:
        email = ent.emails[0]
        # Check if context indicates scam check or both
        if decision.context == "scam_check_email":
            result = await cred_analyze_email(email)
            if not result:
                yield _offline_result(sid, "credential")
                return
            risk = result.get("overall_risk_level", "Unknown")
            human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
            # Use the same formatter but we might want to tailor the message for scam check
            formatted = fmt.format_credential_email(email, result, human_explanation=human_exp or "")
        else:
            result = await cred_analyze_email(email)
            if not result:
                yield _offline_result(sid, "credential")
                return
            risk = result.get("overall_risk_level", "Unknown")
            human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
            formatted = fmt.format_credential_email(email, result, human_explanation=human_exp or "")
        followups = FOLLOWUPS.get("credential", [])
        await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, email)
        yield {
            "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
            "module": "credential", "risk_level": risk,
            "content": formatted,
            "structured": result,
            "followups": followups,
        }
        return

    # Handle phone
    if ent.phone_numbers:
        phone = ent.phone_numbers[0]
        if decision.context == "scam_check_phone":
            result = await cred_analyze_phone_advanced(phone)
        else:
            result = await cred_analyze_phone(phone)
        if not result:
            yield _offline_result(sid, "credential")
            return
        risk = result.get("overall_risk_level", "Unknown")
        human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
        formatted = fmt.format_credential_phone(phone, result, human_explanation=human_exp or "")
        followups = FOLLOWUPS.get("credential", [])
        await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, phone)
        yield {
            "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
            "module": "credential", "risk_level": risk,
            "content": formatted,
            "structured": result,
            "followups": followups,
        }
        return

    # Handle password
    if ent.passwords:
        password = ent.passwords[0]
        email = ent.emails[0] if ent.emails else ""
        username = ent.usernames[0] if ent.usernames else ""
        result = await cred_analyze_password(password, email, username)
        if not result:
            yield _offline_result(sid, "credential")
            return
        risk = result.get("overall_risk_level", "Unknown")
        human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
        formatted = fmt.format_credential_password(result, human_explanation=human_exp or "")
        followups = FOLLOWUPS.get("credential", [])
        await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, "[hidden]")
        yield {
            "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
            "module": "credential", "risk_level": risk,
            "content": formatted,
            "structured": result,
            "followups": followups,
        }
        return

    # Handle card
    if ent.cards:
        card = ent.cards[0]
        result = await cred_analyze_card(card)
        if not result:
            yield _offline_result(sid, "credential")
            return
        risk = result.get("overall_risk_level", "Unknown")
        human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
        formatted = fmt.format_credential_card(result, human_explanation=human_exp or "")
        followups = FOLLOWUPS.get("credential", [])
        await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, "[card]")
        yield {
            "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
            "module": "credential", "risk_level": risk,
            "content": formatted,
            "structured": result,
            "followups": followups,
        }
        return

    # Handle CNIC
    if ent.cnics:
        cnic = ent.cnics[0]
        result = await cred_analyze_national_id(cnic, "cnic")
        if not result:
            yield _offline_result(sid, "credential")
            return
        risk = result.get("overall_risk_level", "Unknown")
        human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
        formatted = fmt.format_credential_national_id(cnic, result, human_explanation=human_exp or "")
        followups = FOLLOWUPS.get("credential", [])
        await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, cnic)
        yield {
            "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
            "module": "credential", "risk_level": risk,
            "content": formatted,
            "structured": result,
            "followups": followups,
        }
        return

    # Handle IBAN
    if ent.ibans:
        iban = ent.ibans[0]
        result = await cred_analyze_iban(iban)
        if not result:
            yield _offline_result(sid, "credential")
            return
        risk = result.get("overall_risk_level", "Unknown")
        human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
        formatted = fmt.format_credential_iban(iban, result, human_explanation=human_exp or "")
        followups = FOLLOWUPS.get("credential", [])
        await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, iban)
        yield {
            "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
            "module": "credential", "risk_level": risk,
            "content": formatted,
            "structured": result,
            "followups": followups,
        }
        return

    # Handle crypto
    if ent.crypto_addresses:
        addr = ent.crypto_addresses[0]["value"]
        result = await cred_analyze_crypto(addr)
        if not result:
            yield _offline_result(sid, "credential")
            return
        risk = result.get("overall_risk_level", "Unknown")
        human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
        formatted = fmt.format_credential_crypto(addr, result, human_explanation=human_exp or "")
        followups = FOLLOWUPS.get("credential", [])
        await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, addr[:20])
        yield {
            "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
            "module": "credential", "risk_level": risk,
            "content": formatted,
            "structured": result,
            "followups": followups,
        }
        return

    # Handle API key
    if ent.api_keys:
        key = ent.api_keys[0]["value"]
        result = await cred_analyze_api_key(key)
        if not result:
            yield _offline_result(sid, "credential")
            return
        risk = result.get("overall_risk_level", "Unknown")
        human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
        formatted = fmt.format_credential_api_key(result, human_explanation=human_exp or "")
        followups = FOLLOWUPS.get("credential", [])
        await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, "[api-key]")
        yield {
            "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
            "module": "credential", "risk_level": risk,
            "content": formatted,
            "structured": result,
            "followups": followups,
        }
        return

    # Fallback: ask for clarification
    yield _prompt_result(sid, "🔑 Please send a credential (email, password, CNIC, card, etc.) to check.", "credential")


async def _handle_profile(sid: str, decision: RouteDecision, session: dict) -> AsyncGenerator[dict, None]:
    yield {"type": "thinking", "content": "👤 Analysing social profile…", "step": 1}

    handle = None
    if decision.entities.handles:
        handle = decision.entities.handles[0]
    elif decision.entities.social_urls:
        handle = decision.entities.social_urls[0].get("handle")
    if not handle:
        yield _prompt_result(sid, "👤 Please send a @username or social handle to analyse.", "profile")
        return

    # Run both credential and profile in parallel (WhatsApp behaviour)
    cred_task = cred_analyze_username(handle)
    prof_task = profile_analyze({"username": handle})
    c_res, p_res = await asyncio.gather(cred_task, prof_task, return_exceptions=True)
    if isinstance(c_res, Exception): c_res = {}
    if isinstance(p_res, Exception): p_res = {}

    # Unified verdict from WhatsApp's username_intelligence
    uv = score_and_rank(handle, c_res, p_res)
    human_exp = await explain_result("profile", uv["risk_level"], p_res, user_question=decision.raw_text)
    formatted = fmt.format_profile_result(handle, {"verdict": uv}, human_explanation=human_exp or "")
    followups = FOLLOWUPS.get("profile", [])
    await store_last_scan(sid, "profile", p_res, uv["risk_level"], uv.get("top_signals", []), decision.raw_text, handle)
    yield {
        "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
        "module": "profile", "risk_level": uv["risk_level"],
        "content": formatted,
        "structured": {"verdict": uv, "credential": c_res, "profile": p_res},
        "followups": followups,
    }


async def _handle_special(sid: str, decision: RouteDecision, session: dict) -> dict:
    action = decision.action

    # ── Help / Greeting ──────────────────────────────────────
    if action == "greeting":
        return _text_result(sid, fmt.HELP_MENU, "help", None)
    if action == "help_menu":
        return _text_result(sid, fmt.HELP_MENU, "help", None)
    if action == "urdu_help_menu":
        return _text_result(sid, fmt.HELP_MENU_URDU, "help", None)
    if action == "general_menu":
        return _text_result(sid, fmt.FULL_CAPABILITY_MENU, "help", None)

    # ── Check / Guided menu ──────────────────────────────────
    if action == "guided_menu":
        return _text_result(sid, fmt.CREDENTIAL_MENU, "help", None)

    # ── Clear session ─────────────────────────────────────────
    if action == "clear_session":
        if session.get("_clear_confirmed"):
        # Delete messages from DB
            try:
                from app.core.database import AsyncSessionLocal
                async with AsyncSessionLocal() as db:
                    from app.services.chat_service_ext import delete_session_messages
                    await delete_session_messages(db, sid)
            except Exception as e:
                logger.error("Failed to delete messages: %s", e)

        # Clear Redis session
            await clear_session(sid)

        # Reset state
            await update_session(sid, state="IDLE", _clear_confirmed=False)

        # Return result with reload flag
            result = _text_result(sid, fmt.format_session_cleared(), "help", None)
            result["reload"] = True
            return result
        else:
            await update_session(sid, _clear_confirmed=True)
            return _text_result(sid, "🗑️ Are you sure you want to clear your session data? Reply *YES* to confirm.", "help", None)
    
    # ── History ──────────────────────────────────────────────
    if action == "history":
        scan_log = session.get("scan_log", [])
        if not scan_log:
            return _text_result(sid, "📋 No scans recorded yet.", "help", None)
        # If user asked for filtered history (e.g., "show link scans")
        # We can parse the raw text for module filter
        raw = decision.raw_text.lower()
        filter_mod = None
        if "link" in raw or "url" in raw:
            filter_mod = "link"
        elif "qr" in raw:
            filter_mod = "qr"
        elif "deepfake" in raw or "face" in raw:
            filter_mod = "deepfake"
        elif "profile" in raw or "account" in raw:
            filter_mod = "profile"
        elif "credential" in raw or "email" in raw or "password" in raw:
            filter_mod = "credential"
        # Use WhatsApp's format_scan_log
        formatted = fmt.format_scan_log(scan_log, filter_module=filter_mod or "")
        return _text_result(sid, formatted, "help", None)

    # ── Cancel ──────────────────────────────────────────────
    if action == "cancel":
        await update_session(sid, state="IDLE", partial_profile={}, pending_entities=[])
        return _text_result(sid, fmt.format_cancel(), "help", None)

    # ── Disambiguation ──────────────────────────────────────
    if action in ("disambiguate", "disambiguate_credential_type"):
        opts = decision.disambig_opts or {}
        if not opts:
            return _error_result(sid, "No options available.")
        await update_session(sid, disambiguation_options=opts, state="AWAITING_DISAMBIGUATION")
        # Build numbered list
        lines = ["Please choose an option:"]
        for key, (module, val, desc) in opts.items():
            lines.append(f"{key}. {desc}")
        content = "\n".join(lines)
    # Chips are the option numbers
        chips = list(opts.keys())  # ["1", "2", "3"]
        return {
            "type": "result",
            "session_id": sid,
            "message_id": str(uuid.uuid4()),
            "module": "help",
            "risk_level": None,
            "content": content,
            "structured": None,
            "followups": chips,  # This will send "1", "2", "3" as clickable chips
        }

    # ── From disambiguation (user selected an option) ──────
    if action == "from_disambiguation":
        # The user's choice is in decision.context (e.g., "both_email", "profile_phone", etc.)
        context = decision.context
        raw = decision.raw_text
        entity = raw  # The raw_text is the entity (email, phone, username)
        if context == "credential_email":
            return await _run_credential_email(sid, entity, session, decision)
        elif context == "profile_email":
            return await _run_scam_check_email(sid, entity, session, decision)
        elif context == "both_email":
            return await _run_both_email(sid, entity, session, decision)
        elif context == "credential_phone":
            return await _run_credential_phone(sid, entity, session, decision)
        elif context == "profile_phone":
            return await _run_scam_check_phone(sid, entity, session, decision)
        elif context == "both_phone":
            return await _run_both_phone(sid, entity, session, decision)
        else:
            # Generic: just re-run classification with the entity
            ent = extract(entity)
            new_d = RouteDecision(primary=Module.CREDENTIAL, action="detect_and_analyze", entities=ent, raw_text=entity)
            return await _handle_credential(sid, new_d, session)

    # ── Prompt actions ──────────────────────────────────────
    if action == "prompt_for_link":
        return _text_result(sid, "🔗 Please send the link (URL) you want me to scan.", "help", None)

    if action == "prompt_for_qr_image":
        await update_session(sid, _pending_image_analysis="qr")
        return _text_result(sid, "📷 Please send the QR code image you want me to scan.", "help", None)

    if action == "prompt_for_deepfake_image":
        await update_session(sid, _pending_image_analysis="deepfake")
        return _text_result(sid, "🎭 Please send the image you want me to check for deepfake manipulation.", "help", None)

    if action == "prompt_for_deepfake_video":
        await update_session(sid, _pending_video_analysis="deepfake")
        return _text_result(sid, "🎬 Please send the video you want me to check for deepfake manipulation.", "help", None)

    if action == "prompt_for_deepfake_image_or_video":
        await update_session(sid, _pending_image_analysis="deepfake", _pending_video_analysis="deepfake")
        return _text_result(sid, "🎭 Please send an image or video to check for deepfake manipulation.", "help", None)

    if action == "prompt_for_any_image":
        await update_session(sid, _pending_image_analysis="auto")
        return _text_result(sid, "📷 Please send the image you want me to analyze. I'll check for QR codes or deepfakes.", "help", None)

    if action == "prompt_for_any_video":
        await update_session(sid, _pending_video_analysis="auto")
        return _text_result(sid, "🎬 Please send the video you want me to analyze. I'll check for QR codes or deepfakes.", "help", None)

    if action == "prompt_for_profile":
        return _text_result(sid, "👤 Please send the @username or social handle you want to analyse.", "help", None)

    if action == "prompt_credential":
        # Show credential menu
        return _text_result(sid, fmt.CREDENTIAL_MENU, "help", None)

    if action.startswith("prompt_for_analyze_"):
        cred_type = action.replace("prompt_for_analyze_", "")
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
        }
        await update_session(sid, state="AWAITING_CREDENTIAL", _pending_credential_type=cred_type)
        return _text_result(sid, prompts.get(cred_type, "Please send the credential you want to check."), "help", None)

    # ── Wrong-X denial ──────────────────────────────────────
    if action == "wrong_x_deny":
        return _text_result(sid, decision.context or "Please send the correct type of input.", "help", None)

    if action == "image_but_wants_link":
        return _text_result(sid, (
            "🔗 It looks like you want to check a *link*, not an image.\n\n"
            "Please send the URL you want me to scan.\n"
            "Example: `https://suspicious-site.com`\n\n"
            "_If you did want to check the image for QR codes or deepfakes, "
            "send it again without any link-related text._"
        ), "help", None)

    if action == "image_but_wants_credential":
        return _text_result(sid, (
            "🔑 It looks like you want to check a *credential*, not an image.\n\n"
            "Please send the credential you want to analyse.\n"
            "Examples: `test@gmail.com` · `Admin@123` · `35202-1234567-1`\n\n"
            "_If you did want to scan the image, send it again without credential keywords._"
        ), "help", None)

    if action == "image_but_wants_profile":
        return _text_result(sid, (
            "👤 It looks like you want to check a *profile*, not an image.\n\n"
            "Please send the @username or social handle you want to check.\n"
            "Example: `@cryptoking99` or `https://instagram.com/user`\n\n"
            "_If you did want to check the image for QR or deepfakes, send it again._"
        ), "help", None)

    # ── Jailbreak block ──────────────────────────────────────
    if action == "jailbreak_block":
        return _text_result(sid, fmt.format_irrelevant("jailbreak_block"), "help", None)

    # ── Summary (Phase 2) ────────────────────────────────────
    if action == "summary":
        return _text_result(sid, "📊 Session summary is a Phase 2 feature. Coming soon!", "help", None)
    
    if action == "prompt_for_analyze_email":
        await update_session(sid, state="AWAITING_CREDENTIAL", _pending_credential_type="email")
        return _text_result(sid, prompts.get("email"), "help", None)
    # But we want no follow-ups for prompts. Since module is "help", it won't show chips.

    # ── Unknown ──────────────────────────────────────────────
    return _error_result(sid, "Unknown command.")


# ── Helper functions for disambiguation actions ──────────────

async def _run_credential_email(sid: str, email: str, session: dict, decision: RouteDecision) -> dict:
    """Run leak monitor (breach check) for email."""
    result = await cred_analyze_email(email)
    if not result:
        return _offline_result(sid, "credential")
    risk = result.get("overall_risk_level", "Unknown")
    human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
    formatted = fmt.format_credential_email(email, result, human_explanation=human_exp or "")
    await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, email)
    return {
        "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
        "module": "credential", "risk_level": risk,
        "content": formatted,
        "structured": result,
        "followups": FOLLOWUPS.get("credential", []),
    }

async def _run_scam_check_email(sid: str, email: str, session: dict, decision: RouteDecision) -> dict:
    """Run scam check (profile/fraud analysis) for email."""
    # Use the credential analyzer's advanced email check
    result = await cred_analyze_email(email)
    if not result:
        return _offline_result(sid, "credential")
    # Add fraud signals from enrichment (if available)
    # For now, we just format as "Scam Check"
    risk = result.get("overall_risk_level", "Unknown")
    # We'll re-purpose the email formatter but change the header
    human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
    formatted = fmt.format_credential_email(email, result, human_explanation=human_exp or "")
    # Override the header to indicate Scam Check
    lines = formatted.split("\n")
    if lines:
        lines[0] = lines[0].replace("Email Analysis", "🕵️ Scam Check")
    formatted = "\n".join(lines)
    await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, email)
    return {
        "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
        "module": "credential", "risk_level": risk,
        "content": formatted,
        "structured": result,
        "followups": FOLLOWUPS.get("credential", []),
    }

async def _run_both_email(sid: str, email: str, session: dict, decision: RouteDecision) -> dict:
    """Run both leak monitor and scam check for email, merged."""
    result = await cred_analyze_email(email)
    if not result:
        return _offline_result(sid, "credential")
    # We'll format as two sections
    risk = result.get("overall_risk_level", "Unknown")
    human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
    # Build merged reply
    lines = [f"🔍 **Combined Analysis for {email}**", ""]
    if human_exp:
        lines.append(human_exp)
        lines.append("")
    # Leak Monitor section
    breach_count = result.get("hibp_count", 0) or 0
    lines.append("━━━ 🔑 **Leak Monitor**")
    if breach_count > 0:
        lines.append(f"🚨 Found in *{breach_count:,}* data breach record(s)")
    else:
        lines.append("✅ Not found in known data breach databases")
    lines.append("")
    # Scam Check section
    lines.append("━━━ 🕵️ **Scam Check**")
    fraud_score = result.get("ipqs_fraud_score", 0) or 0
    if fraud_score >= 75:
        lines.append(f"🚨 High fraud score: {fraud_score}/100 — strong scam signals")
    elif fraud_score >= 40:
        lines.append(f"⚠️ Moderate fraud score: {fraud_score}/100 — exercise caution")
    else:
        lines.append("✅ No scam signals detected")
    lines.append("")
    lines.append(f"🛡️ Overall Risk: {fmt._risk_emoji(risk)} {risk} ({result.get('overall_risk_score', 0)}/100)")
    formatted = "\n".join(lines)
    await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, email)
    return {
        "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
        "module": "credential", "risk_level": risk,
        "content": formatted,
        "structured": result,
        "followups": FOLLOWUPS.get("credential", []),
    }

async def _run_credential_phone(sid: str, phone: str, session: dict, decision: RouteDecision) -> dict:
    """Run leak monitor (breach check) for phone."""
    result = await cred_analyze_phone(phone)
    if not result:
        return _offline_result(sid, "credential")
    risk = result.get("overall_risk_level", "Unknown")
    human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
    formatted = fmt.format_credential_phone(phone, result, human_explanation=human_exp or "")
    await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, phone)
    return {
        "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
        "module": "credential", "risk_level": risk,
        "content": formatted,
        "structured": result,
        "followups": FOLLOWUPS.get("credential", []),
    }

async def _run_scam_check_phone(sid: str, phone: str, session: dict, decision: RouteDecision) -> dict:
    """Run scam check for phone."""
    result = await cred_analyze_phone_advanced(phone)
    if not result:
        # Fallback to regular phone check
        result = await cred_analyze_phone(phone)
        if not result:
            return _offline_result(sid, "credential")
    risk = result.get("overall_risk_level", "Unknown")
    human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
    formatted = fmt.format_credential_phone(phone, result, human_explanation=human_exp or "")
    lines = formatted.split("\n")
    if lines:
        lines[0] = lines[0].replace("Phone Analysis", "🕵️ Scam Check")
    formatted = "\n".join(lines)
    await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, phone)
    return {
        "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
        "module": "credential", "risk_level": risk,
        "content": formatted,
        "structured": result,
        "followups": FOLLOWUPS.get("credential", []),
    }

async def _run_both_phone(sid: str, phone: str, session: dict, decision: RouteDecision) -> dict:
    """Run both leak monitor and scam check for phone, merged."""
    result = await cred_analyze_phone_advanced(phone)
    if not result:
        result = await cred_analyze_phone(phone)
        if not result:
            return _offline_result(sid, "credential")
    risk = result.get("overall_risk_level", "Unknown")
    human_exp = await explain_result("credential", risk, result, user_question=decision.raw_text)
    lines = [f"🔍 **Combined Analysis for {phone}**", ""]
    if human_exp:
        lines.append(human_exp)
        lines.append("")
    # Leak Monitor
    breach_count = result.get("hibp_count", 0) or 0
    lines.append("━━━ 🔑 **Leak Monitor**")
    if breach_count > 0:
        lines.append(f"🚨 Found in *{breach_count:,}* data breach record(s)")
    else:
        lines.append("✅ Not found in known data breach databases")
    lines.append("")
    # Scam Check
    lines.append("━━━ 🕵️ **Scam Check**")
    fraud_score = result.get("ipqs_fraud_score", 0) or result.get("fraud_score", 0)
    if fraud_score >= 75:
        lines.append(f"🚨 High fraud score: {fraud_score}/100 — strong scam signals")
    elif fraud_score >= 40:
        lines.append(f"⚠️ Moderate fraud score: {fraud_score}/100 — exercise caution")
    else:
        lines.append("✅ No scam signals detected")
    # Also show line type / carrier
    ph = result.get("phone", {})
    if ph.get("carrier"):
        lines.append(f"📶 Carrier: {ph.get('carrier')}")
    if ph.get("line_type"):
        lines.append(f"📱 Line type: {ph.get('line_type')}")
    lines.append("")
    lines.append(f"🛡️ Overall Risk: {fmt._risk_emoji(risk)} {risk} ({result.get('overall_risk_score', 0)}/100)")
    formatted = "\n".join(lines)
    await store_last_scan(sid, "credential", result, risk, result.get("all_flags", []), decision.raw_text, phone)
    return {
        "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
        "module": "credential", "risk_level": risk,
        "content": formatted,
        "structured": result,
        "followups": FOLLOWUPS.get("credential", []),
    }


async def _handle_irrelevant(sid: str, decision: RouteDecision, session: dict) -> dict:
    # Use Ollama to generate a friendly off‑topic response (WhatsApp logic)
    raw = decision.raw_text
    action = decision.action  # <-- ADD THIS LINE


    # Detect Urdu/Roman Urdu
    if re.search(r"[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]", raw):
        # Try to classify Urdu intent
        urdu_result = await classify_urdu(raw)
        intent = urdu_result.get("intent", "offtopic")
        extracted = urdu_result.get("extracted", "")
        if intent == "url" and extracted:
            # Re‑route as link
            ent = extract(extracted)
            new_d = RouteDecision(primary=Module.LINK, action="scan", entities=ent, raw_text=extracted)
            # We need to yield; but this is a dict return, so we'll convert
            # For now, just ask the user to send the link in English.
            return _text_result(sid, "📝 I can handle Urdu! Please send the link, email, or username you want to check.", "help", None)
        return _text_result(sid, fmt.format_irrelevant("urdu_message"), "help", None)
    
    if action == "bot_who":
        # Generate intro response (Ollama or fallback)
        try:
            from app.router.ollama_client import answer_cyber_qa
            prompt = "User asked who you are. Introduce yourself as Aegis AI, a cybersecurity assistant built for WhatsApp. Mention you can check links, QR codes, credentials, and deepfakes. Be friendly and concise."
            reply = await answer_cyber_qa(prompt)
            if reply:
                return _text_result(sid, reply, "help", None)
        except Exception:
            pass
        return _text_result(sid, fmt.format_irrelevant("bot_who"), "help", None)


    # Use Ollama for off‑topic
    prompt = f"User said: {decision.raw_text}. This is off‑topic. Politely redirect to cybersecurity help."
    reply = await answer_cyber_qa(prompt) or fmt.format_irrelevant("off_topic")
    return _text_result(sid, reply, "help", None)


async def _handle_cyber_qa(sid: str, decision: RouteDecision, session: dict) -> dict:
    reply = await answer_cyber_qa(decision.raw_text)
    if not reply:
        reply = fmt.format_cyber_qa(decision.raw_text)
    return _text_result(sid, reply, "cyber_qa", None)


async def _handle_followup(sid: str, decision: RouteDecision, session: dict) -> AsyncGenerator[dict, None]:
    yield {"type": "thinking", "content": "💬 Answering follow‑up…", "step": 1}

    last_scan = session.get("last_scan")
    if not last_scan:
        yield _text_result(sid, "I don't have a recent scan to follow up on. Please send something to analyse.", "help", None)
        return

    raw = decision.raw_text
    action = decision.action
    summary = f"Module: {last_scan['module']}, Risk: {last_scan['risk_level']}, Item: {last_scan['item_scanned']}"

    if action == "rescan":
        if last_scan['module'] == "link":
            async for ev in _handle_link(sid, RouteDecision(primary=Module.LINK, raw_text=last_scan["original_input"]), session):
                yield ev
        elif last_scan['module'] == "credential":
            ent = extract(last_scan["original_input"])
            async for ev in _handle_credential(sid, RouteDecision(primary=Module.CREDENTIAL, entities=ent, raw_text=last_scan["original_input"]), session):
                yield ev
        else:
            yield _text_result(sid, f"🔄 Rescan not yet implemented for {last_scan['module']}.", "help", None)
        return

    if action == "explain":
        explanation = await explain_followup(raw, summary)
        yield _text_result(sid, explanation or "I can't explain that further.", "help", None)
        return

    if action == "action_advice":
        explanation = await explain_followup(raw, summary)
        yield _text_result(sid, explanation or "I can't give advice on that.", "help", None)
        return

    # Fallback: use Ollama to classify
    intent = await classify_followup(raw, summary)
    action2 = intent.get("intent", "unrelated")
    if action2 == "rescan":
        if last_scan['module'] == "link":
            async for ev in _handle_link(sid, RouteDecision(primary=Module.LINK, raw_text=last_scan["original_input"]), session):
                yield ev
        else:
            yield _text_result(sid, f"🔄 Rescan for {last_scan['module']} not yet implemented.", "help", None)
    elif action2 in ("explain", "action_advice"):
        explanation = await explain_followup(raw, summary)
        yield _text_result(sid, explanation or "I can't explain that further.", "help", None)
    else:
        yield _text_result(sid, "How can I help you with the last scan? Ask me to explain, rescan, or give advice.", "help", None)

        

async def _handle_multi(sid: str, decision: RouteDecision, session: dict, media_bytes: bytes, media_type: str) -> AsyncGenerator[dict, None]:
    # WhatsApp runs routes concurrently using asyncio.gather
    # For now, we'll implement a simple version
    routes = decision.concurrent_routes
    if not routes:
        yield _error_result(sid, "No routes in multi-dispatch.")
        return

    # Create tasks
    tasks = []
    for r in routes:
        # We need to call _dispatch for each route
        # But _dispatch is a generator, so we need to collect results
        # This is simplified – we'll just run them sequentially for now
        # In a full implementation, we'd use asyncio.gather with proper streaming
        # For now, we'll run them sequentially and concatenate
        async for ev in _dispatch(sid, r, session, media_bytes, media_type):
            if ev.get("type") == "result":
                # We'll collect the final result
                # For simplicity, just yield one result with combined content
                pass

    # Fallback
    yield _error_result(sid, "Multi‑module not fully implemented yet.")


# ── Mismatch detection (copied from WhatsApp) ────────────────
def _detect_mismatch(raw_text: str, session: dict) -> Optional[str]:
    """
    Detect wrong X — e.g., user says 'scan this link' but sends an email.
    Returns a polite redirect message, or None.
    """
    from app.router.extractor import extract as _ext

    t = raw_text.lower()
    ent = _ext(raw_text)

    # State-based mismatches
    state = session.get("state", "IDLE")
    if state == "AWAITING_CREDENTIAL":
        if ent.urls or ent.social_urls:
            return (
                "🔗 That looks like a *link*, not a credential.\n\n"
                "I'm waiting for a credential (email, password, CNIC, etc.). "
                "Please send the credential you want to check, or type /cancel."
            )

    # Text-based mismatches
    if "scan this link" in t or "scan this url" in t or "check this link" in t:
        if ent.emails and not ent.urls:
            return (
                "📧 That's an *email address*, not a link.\n\n"
                "• To scan a link → send the URL (e.g., `https://example.com`)\n"
                "• To check this email for breaches → just send the email address"
            )
        if ent.cnics and not ent.urls:
            return (
                "🪪 That's a *CNIC number*, not a link.\n\n"
                "• To scan a link → send the URL\n"
                "• To check this CNIC → just send the CNIC number"
            )
        if ent.phone_numbers and not ent.urls:
            return (
                "📱 That's a *phone number*, not a link.\n\n"
                "• To scan a link → send the URL\n"
                "• To check this phone number → just send the number"
            )

    return None


# ── Helper result builders ────────────────────────────────────
def _text_result(sid: str, content: str, module: str, risk: Optional[str]) -> dict:
    # Only show follow-ups for actual analysis results, not prompts/errors
    show_followups = module in ("link", "qr", "credential", "profile", "deepfake", "sms_scam", "cyber_qa")
    return {
        "type": "result", "session_id": sid, "message_id": str(uuid.uuid4()),
        "module": module, "risk_level": risk,
        "content": content,
        "structured": None,
        "followups": FOLLOWUPS.get(module, []) if show_followups else [],
    }

def _prompt_result(sid: str, content: str, module: str) -> dict:
    return _text_result(sid, content, module, None)

def _error_result(sid: str, msg: str) -> dict:
    return _text_result(sid, f"⚠️ {msg}", "help", None)

def _offline_result(sid: str, module: str) -> dict:
    return _text_result(sid, f"⚠️ {module.title()} service is offline. Please try again later.", "help", None)