"""
app/router/intent.py — Intent classification and routing.

FIXES:
  FIX-001: Greetings (salam, assalamoalaikum, walaikum, etc.) now caught EARLY
            before username extraction turns them into disambiguation.
  FIX-002: Image + link/credential/profile text → ignore image, ask for entity.
  FIX-003: Massively expanded _MISSING_LINK_KEYWORDS.
  FIX-004: QR follow-up keywords added to _FOLLOWUP_EXPLAIN.
  FIX-005: "scan this X + wrong Y" → mismatch detection.
  FIX-006: All keyword lists expanded.
  FIX-007: Roman Urdu / Urdu detection fires early.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional

from app.router.extractor import ExtractedEntities, SOCIAL_PLATFORMS


class Module(str, Enum):
    LINK       = "link"
    QR         = "qr"
    CREDENTIAL = "credential"
    PROFILE    = "profile"
    FOLLOWUP   = "followup"
    CYBER_QA   = "cyber_qa"
    SPECIAL    = "special"
    IRRELEVANT = "irrelevant"
    MULTI      = "multi"
    DEEPFAKE   = "deepfake"


@dataclass
class RouteDecision:
    primary: Module
    secondary: Optional[Module] = None
    entities: Any = None
    action: str = ""
    needs_disambig: bool = False
    disambig_opts: dict = field(default_factory=dict)
    command: str = ""
    raw_text: str = ""
    context: str = ""
    concurrent_routes: List["RouteDecision"] = field(default_factory=list)


# ============================================================================
# Keyword sets — FIX-006: all lists expanded
# ============================================================================

_QR_KEYWORDS = {
    "qr", "qr code", "scan qr", "decode qr", "what's in this qr", "read qr",
    "qr scan", "qr decode", "scan this qr", "check qr", "is this qr safe",
    "qr image", "qr code image", "qr code scan", "is this qr code", "scan the qr",
    "qr code safe", "qr security", "is this qr legit", "qr video", "qr in video",
    "whats in this qr", "what's in this qr", "whats in the qr",
    "what is in this qr", "what is in the qr",
    "what does this qr say", "what does this qr code say", "what does the qr say",
    "read this qr", "read the qr code", "decode this qr", "decode the qr",
    "scan the qr code", "check this qr code", "analyse this qr", "analyze this qr",
    "is this a safe qr", "is this qr dangerous", "is this qr code safe",
    "what url is in this qr", "what link is in this qr", "qr code check",
    "tell me what this qr contains", "what does qr contain",
    "scan qr code", "qr scanner", "read qr code",
    "is qr safe", "is the qr safe", "qr safe or not",
}

_VIDEO_KEYWORDS = {
    "video", "videos", "clip", "movie", "film", "footage", "recording",
    "scan video", "analyze video", "analyse video", "check video",
    "is this video real", "is this video fake", "video deepfake",
    "scan this video", "check this video", "video analysis",
    "watch this", "watch video", "check this clip", "analyse this clip",
    "this recording", "video file",
}

_DEEPFAKE_KEYWORDS = {
    "deepfake", "deep fake", "ai generated", "ai image", "ai face", "ai photo",
    "fake face", "fake image", "fake photo", "fake video", "fake picture",
    "check if real", "check if fake", "real or fake", "authentic",
    "manipulated", "photoshopped", "edited photo", "face swap", "faceswap",
    "generated face", "gan face", "synthetic face", "ai avatar",
    "is this person real", "is this face real", "detect fake",
    "verify image", "image verification", "photo verification",
    "check this face", "is this ai", "ai generated image",
    "voice clone", "voice cloning", "cloned voice", "synthetic voice",
    "/deepfake", "scan for deepfake", "deepfake check", "deepfake scan",
    "is this image real", "is this image fake", "is this a deepfake",
    "check if this image is real", "check if this image is fake",
    "can you tell if this is fake", "can you tell if this is real",
    "does this look fake", "does this look real",
    "is this a fake person", "ai generated face",
    "fake profile picture", "is this profile picture real",
    "is this a real face", "is this a fake face", "real human", "fake human",
    "is this a real human", "human or ai",
    "does this person exist", "does this face exist",
    "is this photo real", "is this picture real", "is this fake",
}

_SCAN_IMAGE_KEYWORDS = {
    "scan this image", "scan image", "analyze this image", "analyse this image",
    "check this image", "check image", "inspect this image", "image analysis",
    "run analysis on this image", "analyse this picture", "check this picture",
    "scan this picture", "check this photo", "analyze this photo",
    "please analyze this image", "analyze image", "check photo",
    "analyze this", "inspect this", "look at this",
    # FIX-10: generic image scan
    "scan this", "check this for me", "analyse this for me",
    "tell me about this image", "what is in this image",
}

# FIX-10: Face/deepfake specific scan requests
_SCAN_FACE_KEYWORDS = {
    "scan this face", "scan this person", "scan this photo for face",
    "is this face real", "is this person real", "check this face",
    "check this person", "analyze this face", "analyse this face",
    "scan for face", "face scan", "face check", "face analysis",
    "deepfake face", "check face", "is this a real face",
    "is this face deepfake", "face deepfake", "detect face",
    "scan for deepfake", "deepfake scan", "deepfake check",
    "scan this deepfake image", "check deepfake image",
    "is this image deepfake", "analyze for deepfake",
    "scan this for deepfake", "check this for deepfake",
}

# FIX-10: Video scan requests
_SCAN_VIDEO_KEYWORDS = {
    "scan this video", "scan video", "analyze this video", "analyse this video",
    "check this video", "check video", "video scan", "video analysis",
    "is this video real", "is this video fake", "video deepfake",
    "scan for deepfake in video", "deepfake video", "video deepfake check",
    "analyze video for deepfake", "check video for deepfake",
    "is this a real video", "is this video manipulated",
    "scan this clip", "check this clip", "analyze this clip",
    "is this clip real", "fake video", "scan this recording",
}

_PROFILE_KEYWORDS = {
    "check this profile", "analyse the profile", "analyze the profile",
    "verify this profile", "check this account", "analyse this account",
    "check his profile", "check her profile", "check their profile",
    "this user is approaching me", "this person is contacting me",
    "is this account real", "is this account fake", "is this account safe",
    "is this person real", "is this a real person", "is this user real",
    "who is this person", "who is this user", "who is this account",
    "can you check this profile", "can you verify this",
    "is this profile real", "is this profile fake", "verify this user",
    "i want to check a profile", "want to check this profile",
    "check if this is real", "check if this is fake",
    "someone is approaching me", "this account messaged me",
    "is this legit", "is this legitimate", "is this genuine",
    "fake account", "fake profile", "fake user", "bot account",
    "is this a bot", "is it a bot", "real account", "real person",
    "scammer profile", "scammer account", "looks suspicious",
    "suspicious profile", "suspicious account",
    "check the scammer", "is this scammer", "this seems fake",
    "doesn't look real", "looks fake", "check this person",
    "analyse this user", "analyze this user", "verify this account",
    "is this user legit", "check if this account is real", "account check",
    "profile check", "run profile check", "social media check",
    "is this instagram real", "is this twitter real", "is this facebook real",
    "he messaged me", "she messaged me", "they messaged me",
    "this user sent me", "got a message from", "stranger messaged",
    "unknown person", "unknown account", "unknown user",
    "is this person trustworthy", "can i trust this account",
    "should i trust this user", "profile looks suspicious",
}

_LINK_KEYWORDS = {
    "safe", "phishing", "malicious", "scan this link", "is this link",
    "check this link", "check this url", "scan link", "scan url",
    "dangerous", "legit", "legitimate", "virus", "malware", "spyware",
    "is this website safe", "is this site safe", "safe to visit",
    "safe to open", "safe to click", "should i open", "should i click",
    "my boss sent", "someone sent", "received this", "got this link",
    "is this website", "check this website", "is this site",
    "can you check this link", "can you scan this", "scan this url",
    "is this safe to click", "i got this link", "i received this link",
    "someone shared this", "my friend sent this", "can i open this",
    "should i trust this", "is this trustworthy", "is this real link",
    "check if this is safe", "verify this link", "analyse this link",
    "this link looks suspicious", "suspicious link", "looks like phishing",
    "is this url safe", "check this website link", "website safe",
    "url safe", "link safe", "link check", "url check", "website check",
    "is this domain safe", "domain safe", "domain check",
    "can i visit this", "can i click this", "is it ok to click",
    "verify this url", "verify this website", "verify this site",
    "sent me this link", "sent me this url", "sent me a link",
    "is this link ok", "link ok", "url ok",
    "forwarded this link", "forwarded me a link",
}

# FIX-003: Massively expanded — catches all "is this safe to click", etc.
_MISSING_LINK_KEYWORDS = {
    "scan this link", "scan this url", "check this link", "check this url",
    "scan the link", "check the link", "scan link", "check link",
    "analyze this link", "analyse this link", "can you scan this link",
    "please scan this link", "scan this for me", "check this for me",
    "i want to scan a link", "need to check a link", "scan it please",
    # "is this X safe/dangerous" without URL
    "is this link safe", "is this url safe", "is this website safe",
    "is this site safe", "is this link dangerous", "is this safe to click",
    "is this safe to open", "is this safe to visit", "is this link legit",
    "is this link legitimate", "is this link phishing", "is this link malicious",
    "is this link a virus", "is this link malware",
    "should i click this", "should i click this link", "should i open this link",
    "should i visit this link", "should i open this url",
    "can i click this", "can i click this link", "can i open this link",
    "can i visit this link", "can i open this url",
    "is it safe to click", "is it safe to open", "is it safe to visit",
    "is it safe to click this", "is it safe to open this",
    "is this link ok to click", "ok to click", "ok to open", "ok to visit",
    "is this a safe link", "is this a safe url", "is this a safe website",
    "is this a phishing link", "is this phishing", "is this a virus link",
    "check if this link is safe", "check if this url is safe",
    "this link looks suspicious", "suspicious link", "suspicious url",
    "check this suspicious link", "this url looks suspicious",
    "got this link", "got this url", "received this link", "received this url",
    "someone sent a link", "someone shared a link", "my friend sent a link",
    "my boss sent a link", "boss sent me a link", "got a link",
    "i got a link", "i received a link", "i have a link",
    "i want to check a link", "want to check this link", "want to check a link",
    "need to check this link", "help me check this link",
    "link check please", "please check this link", "please check this url",
    "is this a safe website", "website check please", "verify this website",
    "link scan please", "url scan please",
    # Common short phrasings that get username-extracted
    "can i open this", "can i click this", "ok to click", "ok to open",
    "is this url dangerous", "is this link bad", "is this dangerous",
    "is this safe", "is this ok",
}

_MISSING_QR_KEYWORDS = {
    "scan qr", "check qr", "scan qr code", "check qr code",
    "i have a qr code", "i want to scan a qr", "need to scan qr",
    "scan my qr", "analyse qr", "analyze qr", "decode qr",
    "qr code scan", "qr scanner", "scan the qr", "scan the qr code",
    "read this qr", "read qr code", "check this qr",
}

_MISSING_CREDENTIAL_KEYWORDS = {
    "check my password", "check password", "is my password safe",
    "is my password strong", "is my email leaked", "check my email",
    "check email breach", "is my email in breach", "check for data breach",
    "check my cnic", "check cnic", "verify cnic",
    "check my card", "check credit card", "check debit card",
    "check my iban", "verify iban", "check iban",
    "check my phone number", "check phone", "verify phone",
    "check api key", "check my api key", "is this api key safe",
    "check crypto address", "verify crypto",
    "scan credential", "check credential",
}

_MISSING_PROFILE_KEYWORDS = {
    "check this profile", "check this account", "check this user",
    "analyse this profile", "analyze this account", "verify this profile",
    "check fake account", "is this account real", "is this user real",
    "check if this is fake", "profile check", "account check",
    "check for fake account", "is this a bot",
    "check this person", "verify this person",
}

_CREDENTIAL_KEYWORDS = {
    "password", "check my password", "is this card", "leaked", "breached",
    "breach", "credential", "api key", "token", "cnic", "passport",
    "iban", "bitcoin", "ethereum", "crypto", "email address", "check email",
    "check an email", "verify email", "check this email",
    "check this phone", "check my card", "check my iban",
    "want to check", "i want to check", "check a",
    "is it leaked", "is it breached", "check for breach", "data breach",
    "is my password safe", "is my password strong", "how strong is",
    "check my phone number", "phone number check", "email breach",
    "have i been pwned", "pwned", "hibp", "data leak",
    "credit card check", "card number check", "card check",
    "cnic check", "national id check", "id check",
    # FIX-11: massively expanded
    "check my email", "check my phone", "check my number",
    "is my email safe", "is my email secure", "email secure",
    "check my credentials", "credential check", "security check",
    "is this email real", "is this email valid", "email valid",
    "was my email hacked", "was my data leaked", "was i hacked",
    "check my account", "account breach", "account hacked",
    "check this number", "is this number safe", "number check",
    "verify this number", "is this phone valid", "phone valid",
    "check bitcoin address", "check ethereum address", "crypto check",
    "check my api", "is this token valid", "token valid",
    "check this key", "api check", "is this api key real",
    "national id", "check my national id", "verify national id",
    "cnic verify", "check pakistani id", "pakistan id",
    "check this iban", "iban valid", "is this iban valid",
    "bank account check", "check bank account",
    "check my password strength", "password strength",
    "strong password", "weak password", "password score",
    "check for leaks", "leak check", "breach check",
    "check if hacked", "was this hacked", "hacked check",
    "security audit", "credential audit", "identity check",
    "check my identity", "verify my identity", "identity verify",
}

_HISTORY_KEYWORDS = {
    "/history", ".history", "history", "show history", "session history", "our history",
    "what have we done", "what did we check", "what was scanned",
    "previous scans", "past scans", "recent scans",
    "what have i scanned", "what did i scan", "show me history",
    "list scans", "my scans", "scan history", "our scans",
    "what we analyzed", "what we scanned",
    "links we scanned", "links we have scanned",
    "what links did we scan", "scanned today", "checked today",
    "show me scans", "show scans",
    "how many scans", "session summary", "analysis summary",
    "what did we do", "what have you scanned", "summary",
    "how many high risk", "how many threats", "how many safe",
    "my link scans", "my qr scans", "my credential scans",
    "show link scans", "show qr scans", "show credential scans",
    "what did we analyse", "what did we analyze",
    "scan log", "today's scans", "what happened today",
    "total scans", "scan count",
    "recent activity", "activity log",
    # Type-specific history filters
    "show deepfake scans", "show profile scans", "show smishing scans",
    "my deepfake scans", "my profile scans", "my smishing scans",
    "deepfake history", "profile history", "link history", "qr history",
    "credential history", "smishing history",
    "what links did i check", "what qr codes did i scan",
    "what credentials did i check", "what profiles did i check",
    "what emails did i check", "what phones did i check",
    "what passwords did i check", "what cnics did i check",
    "all my scans", "everything i scanned", "full history",
    "show all", "list all scans", "list everything",
    "what threats did i find", "what was dangerous",
    "what was safe", "what was risky", "how many threats",
    "threats today", "safe scans today", "risky scans today",
    "any threats", "any risks found", "any danger detected",
    "show results", "all results", "previous results",
    "today's results", "session results",
}

_CLEAR_KEYWORDS = {
    "clear", "delete", "forget", "remove", "erase", "wipe", "clean",
    "clear data", "delete data", "clear session", "delete session",
    "clear history", "delete history", "forget everything", "start fresh",
    "reset", "clean the data", "clear all", "delete all", "wipe data",
    "remove everything", "privacy", "gdpr", "clear the session",
    "clean history", "erase history", "delete the data",
    "please delete", "delete my data", "remove my data", "wipe everything",
    "start over", "fresh start", "restart session", "new session",
    "forget my data", "remove session", "purge", "purge data",
    "clear everything", "delete everything", "erase everything",
    "i want my data deleted", "delete all my data", "remove all data",
    "clear my data", "clear my history", "remove my history",
    "do not store", "dont store", "remove all", "wipe all",
}

# FIX-004: QR follow-up keywords added + general "what's in" phrases
_FOLLOWUP_RESCAN = {
    "scan it again", "rescan", "re-scan", "recheck", "re check",
    "scan again", "check again", "once more", "another scan", "again",
    "retry", "re-run", "run again", "scan once more", "check once more",
    "run it again", "do it again", "try again", "repeat",
    "scan this again", "check this again", "do another scan",
    "run the scan again", "run it once more", "one more time",
    "re scan", "re check", "redo", "do over", "re analyse",
    "re-analyse", "re analyze", "re-analyze", "analyse again",
    "analyze again", "check one more time", "verify again",
    "double check", "second scan", "run once more",
}

_FOLLOWUP_EXPLAIN = {
    "what does that mean", "what does this mean", "explain", "what are flags",
    "tell me more", "elaborate", "explain the flags", "what are these flags",
    "what does it mean", "breakdown", "more details", "i don't understand",
    "what is that", "clarify", "can you explain", "what does score mean",
    "what does the score mean", "more info", "details please",
    "what does domain age mean", "what does domain age", "domain age",
    "what does confidence mean", "what does entropy mean",
    "what does tld mean", "what is tld", "what is entropy",
    "what does this score", "why is it", "why is this", "why was it",
    "what does", "what is this", "tell me about this",
    "how does this work", "what does flag mean", "what do the flags",
    "explain more", "can you elaborate", "break it down", "break this down",
    "what does antivirus mean", "what is virustotal", "what is vt",
    "what does ssl mean", "what is https", "what is a redirect",
    "what is phishing pattern", "what is typosquatting",
    "what does nxdomain mean", "what does luhn mean", "what is luhn",
    "what does this result mean", "what does the result mean",
    "explain the result", "explain the score", "explain the risk",
    "what is the risk", "what is the score", "how was this scored",
    "what are signals", "what are these signals", "what do signals mean",
    # FIX-004: QR-specific follow-up keywords
    "whats in this qr", "what's in this qr", "whats in the qr",
    "what's in the qr", "what is in this qr", "what is in the qr",
    "what does this qr contain", "what does the qr contain",
    "what does this qr say", "what does the qr say",
    "what was in that qr", "what was the qr about",
    "tell me what the qr said", "what did the qr contain",
    "what url was in the qr", "what link was in the qr",
    "where does this qr go", "where does the qr lead",
    "is the qr safe", "was that qr safe", "was the qr dangerous",
    "was the qr safe", "is the qr dangerous", "is that qr safe",
    "was that qr dangerous", "is this qr dangerous", "is this qr ok",
    "what type of qr", "what kind of qr", "what was the qr type",
    "whats in this", "what's in this", "what is in this",
    "tell me what this contains", "what does this contain",
    "what does this say", "what did it find", "what was found",
    "what is the content", "what is the payload",
    "tell me the result", "what was the result", "what did you find",
    "what did the scan find", "what did the scan say",
    "what were the flags", "what were the issues",
    # FIX-11: even more explain keywords
    "explain what happened", "explain what this means",
    "what does breach mean", "what does leaked mean", "what does hacked mean",
    "what does flagged mean", "what does suspicious mean",
    "what does safe mean", "what does risk mean", "what does score mean",
    "tell me in simple words", "explain simply", "explain in plain words",
    "what is this about", "what is going on", "what happened here",
    "i am confused", "i don't understand this", "i cant understand",
    "please explain", "can u explain", "can you explain this",
    "what are the details", "show me details", "give me details",
    "more information", "more info please", "tell me everything",
    "what are the findings", "what did it detect", "what was detected",
    "what are red flags", "what are warning signs", "what are signals",
    "why is it risky", "why is it safe", "why did it flag",
    "why did it fail", "why did it pass", "why was it flagged",
    "what made it dangerous", "what made it safe", "what triggered",
    "how was it scored", "how is the score calculated", "scoring method",
    "what is risk level", "explain the risk", "explain the level",
    "what does high risk mean", "what does low risk mean",
    "what does medium risk mean", "what does critical mean",
    "what happened with my data", "what was exposed", "what was leaked",
    "how many times was it breached", "how many breaches",
    "when was it breached", "which databases", "which websites",
    "what was compromised", "what information was leaked",
    "is it a false positive", "could it be wrong", "are you sure",
    "double check this", "verify this result", "confirm this",
}

_FOLLOWUP_ACTION = {
    "what should i do", "what to do", "what do i do",
    "is that bad", "is this bad", "how bad is it", "should i worry",
    "is it dangerous", "what now", "what next", "am i safe",
    "should i be worried", "what action", "recommend", "advice",
    "how do i fix", "what should i", "is it serious", "is this serious",
    "what can i do", "steps to take", "is this dangerous", "should i click",
    "should i open", "should i visit", "what do i do now", "i clicked it",
    "i already clicked", "what if i clicked", "is my device safe",
    "what happens now", "what happens next", "how do i stay safe",
    "what do i do if", "should i be scared", "is my data safe",
    "could i be hacked", "am i at risk", "was i hacked",
    "did they get my data", "should i change my password",
    "should i contact my bank", "should i report this",
    "what are the consequences", "how serious is this",
    "is my account safe", "is my phone safe", "is my computer safe",
    "i entered my password", "i gave my details", "i shared my otp",
    "i clicked the link", "i opened it", "i visited the site",
    "what should i do now", "how to protect myself",
    "what should i do about this", "how do i handle this",
    "how can i protect myself", "what precautions should i take",
    "is this something to worry about", "should i be concerned",
    "what are my options", "what do you recommend",
    "is it too late", "have i been compromised", "am i compromised",
    "help me", "what do i need to do", "urgent what to do",
    # FIX: short "is it" follow-up phrases
    "is it safe", "is this safe", "is it ok", "is this ok",
    "is it fine", "is this fine", "is it dangerous", "is this dangerous",
    "is it bad", "is this bad", "is it okay", "is this okay",
    "is it secure", "is this secure", "is it clean", "is this clean",
    "is it legit", "is this legit", "is it real", "is this real",
    "is it harmful", "is this harmful", "is it safe to use",
    "can i use it", "can i trust it", "can i proceed",
    "safe or not", "dangerous or not", "ok or not", "risky or not",
    # FIX-11: even more
    "is it trustworthy", "is this trustworthy", "can i rely on it",
    "is it genuine", "is this genuine", "is it authentic",
    "should i be careful", "should i be cautious", "need to worry",
    "is my data safe", "is my info safe", "is my information safe",
    "did they steal", "was my data stolen", "data stolen",
    "am i protected", "are i protected", "is it protected",
    "what happened to my data", "what happened to my info",
    "what are the risks", "how risky is this", "what is the danger",
    "how likely is", "what is the chance", "what are the odds",
    "is it worth worrying", "not worth worrying", "nothing to worry",
    "should i take action", "action needed", "no action needed",
    "is it a threat", "is this a threat", "is it malicious",
    "is this malicious", "is it infected", "is this infected",
    "is my phone at risk", "is my account at risk", "is my bank at risk",
    "did someone access", "could someone access", "can they access",
    "will i be hacked", "could i be hacked", "was i hacked already",
    "what should i tell", "should i tell my boss", "should i inform",
    "should i change", "need to change", "must i change",
    "is it serious enough", "how serious is", "how bad is",
    # Scammer/phone/number follow-ups
    "is this number a scammer", "is this a scammer", "is this person a scammer",
    "is this number safe", "is this number legit", "is this number trustworthy",
    "can i trust this number", "should i pick up", "should i call back",
    "is this number spam", "is this a spam number", "is this a fraud number",
    "is this number fraudulent", "is this a real number",
    "is it a scammer", "is he a scammer", "is she a scammer",
    "is this email a scammer", "is this email safe", "is this email trustworthy",
    # Password follow-ups
    "is my password strong", "is my password weak", "is my password good",
    "is it strong enough", "is it weak", "is it strong", "is it secure enough",
    "is this password safe", "is this password good", "is this password strong",
    "how strong is my password", "how good is", "how weak is",
    "is it a good password", "is it a bad password",
    "should i use this password", "is this password ok",
    "what is the strength", "what is my password score",
    # Email/number breach follow-ups
    "is my email safe", "is my email compromised", "is my email at risk",
    "is this email compromised", "is this email leaked",
    "is this email in a breach", "was this email breached",
    "is my number safe", "is my number compromised", "is my number at risk",
    "is this number in a breach", "was this number breached",
    # Credential/CNIC/card validity follow-ups
    "is it valid", "is this valid", "is it legitimate", "is this legitimate",
    "is it real", "is this real", "is it fake", "is this fake",
    "is it genuine", "is this genuine", "does it work", "is it working",
    "is it expired", "is this expired", "is it active", "is this active",
    "is it correct", "is this correct", "is it a valid number",
    "is this cnic valid", "is this card valid", "is this iban valid",
    # Breach specific
    "is it breached", "is this breached", "was it breached", "was this breached",
    "is it leaked", "was it leaked", "was this leaked",
    "has it been breached", "has this been breached",
    "is it in a breach", "is it in any breach", "is it compromised",
    "was it compromised", "is this compromised",
    # Profile/person trust follow-ups
    "is this person trustworthy", "can i trust this person", "should i trust them",
    "is this user trustworthy", "can i trust this account", "is this account safe",
    "is this person safe", "should i trust this user", "should i trust this account",
    "is this person real", "is this a real person", "is this user real",
    "is this account real", "is this account fake", "is this person fake",
    "should i follow them", "should i accept their request",
    "is this profile safe", "can i trust this profile",
}

_COMMANDS = {
    "/scan":     (Module.LINK,       "scan"),
    "/qr":       (Module.QR,         "qr"),
    "/profile":  (Module.PROFILE,    "profile"),
    "/check":    (Module.SPECIAL,    "guided_menu"),
    "/generate": (Module.QR,         "generate"),
    "/clear":    (Module.SPECIAL,    "clear_session"),
    "/forget":   (Module.SPECIAL,    "clear_session"),
    "/cancel":   (Module.SPECIAL,    "cancel"),
    "/history":  (Module.SPECIAL,    "history"),
    "/status":   (Module.LINK,       "async_status"),
    "/help":     (Module.SPECIAL,    "help_menu"),
    "/summary":  (Module.SPECIAL,    "summary"),
    "/detect":   (Module.CREDENTIAL, "detect_and_analyze"),
    "/deepfake": (Module.DEEPFAKE,   "analyze_image"),
}

# FIX-001: Expanded greeting words — Pakistani + English
_GREETING_WORDS = {
    "hi", "hello", "hey", "salam", "salaam", "assalam", "aoa",
    "good morning", "good evening", "good afternoon", "hii", "helo",
    "hy", "start", "begin",
    # Pakistani greetings
    "assalamoalaikum", "assalamu alaikum", "assalamu", "walaikum",
    "walaikumsalam", "walaikum salam", "wa alaikum", "wa alaikum salam",
    "aslam o alaikum", "aslam", "aslamoalaikum",
    "salam bhai", "salam ji", "hi there", "hey there",
    "good day", "greetings", "howdy", "sup", "whats up", "what's up",
    "namaste", "namaskar", "ji salam", "salam karo",
    "as salam", "assalamualaikum", "salam alaikum",
}

_GENERAL_MENU_KEYWORDS = {
    "what can you check", "what can you do", "what can you scan",
    "what can you analyse", "what can you analyze", "what services",
    "show me what you can", "what do you offer", "what are you able",
    "what are your features", "how can you help", "what are your services",
    "what are your capabilities", "what do you support", "list services",
    "show services", "show features", "show capabilities", "show options",
    "what types", "what kind of", "what all can", "how do i use",
    "guide me", "get started", "what should i send", "how to use",
    "show me the menu", "show menu", "all features", "all services",
    "what are you good at", "what do you analyse", "what do you check",
    "help me get started", "how to begin", "where to start",
    "what can i ask you", "what can i send you", "what can i check",
    "how does this work", "how do i use this",
}

_JAILBREAK_PATTERNS = [
    r"ignore.*previous.*instruction",
    r"forget.*you.*are",
    r"pretend.*you.*are",
    r"act.*as.*if",
    r"you are now",
    r"override.*system",
    r"jailbreak",
    r"dan mode",
    r"developer mode",
    r"bypass.*filter",
]

_URDU_INDICATORS = re.compile(
    r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]"
)
_ROMAN_URDU = re.compile(
    r"\b(kya|hai|kar|nahi|aap|mera|meri|yeh|woh|tha|thi|se|pe|ko|ka|ki|ke|"
    r"bhi|aur|lekin|phir|ab|hum|tum|ap|ho|hoon|hun|shukriya|meherbani|theek|"
    r"mahfooz|karo|kren|dijiye|batao|btao|kijiye|kijye|"
    r"ye|isko|usko|wala|wali|wale|nahin|bilkul|zaroor)\b",
    re.IGNORECASE,
)
_ANGRY_WORDS = {
    "useless", "stupid", "idiot", "worst", "hate", "angry", "frustrated",
    "pathetic", "rubbish", "trash", "garbage", "terrible", "awful",
    "horrible", "disgusting", "ridiculous", "absurd", "nonsense", "crap",
    "worthless", "pointless", "broken", "buggy",
    "annoying", "irritating", "disappointing", "disgusted", "fed up",
    "furious", "outraged", "ridicule", "joke", "laughable", "failure",
    "worst ever", "not working", "doesnt work", "wont work",
}

_CYBER_QA_KEYWORDS = {
    "what is phishing", "what is 2fa", "what is vpn", "what is ransomware",
    "what is malware", "how to create a strong password", "is public wifi",
    "what is social engineering", "report cybercrime", "dark web",
    "is my phone hacked", "how does", "what is a",
    "how do i create", "how to make", "how to set up", "how to enable",
    "what is 2 factor", "two factor", "two-factor",
    "how to protect", "how to prevent", "what is sim swap",
    "how to report", "how to file complaint", "how to change password",
    "tell me about", "explain phishing", "explain ransomware",
    "what is hacking", "what is deepfake", "how safe is",
    "what should i do if", "what happens if i click",
    "deepfake", "deep fake", "ai generated", "voice cloning",
    "cyber security", "cybersecurity tip", "online safety",
    "what is spyware", "what is trojan",
    "how to stay safe", "is it safe to", "can hackers",
    "how do hackers", "what is a data breach", "what is identity theft",
    "what is a keylogger", "what is a botnet", "what is ddos",
    "how to secure my account", "how to secure my phone",
    "how to detect malware", "how to remove malware",
    "what is end to end encryption", "what is encryption",
    "what is a firewall", "what is a proxy",
    "how do i know if im hacked", "signs of hacking",
    "what is otp fraud", "what is sim hijacking",
    "pakistan cyber law", "cybercrime pakistan", "fia cybercrime",
    "how to report fraud", "how to report scam",
}

# ============================================================================
# Main classifier
# ============================================================================

def classify(text: str, ent: ExtractedEntities, session: dict) -> RouteDecision:
    text_lower = text.lower().strip()
    state      = session.get("state", "IDLE")
    last_scan  = session.get("last_scan")

    # ── AWAITING states ───────────────────────────────────────────────────────
    if state == "AWAITING_DISAMBIGUATION":
        result = _handle_disambiguation_response(text_lower, session)
        if result.action == "disambiguate_retry":
            return _reclassify_escaped(text, ent, session)
        return result

    if state == "AWAITING_CREDENTIAL":
        _choice = text_lower.strip()
        _MENU_MAP = {
            "1": "analyze_email", "2": "analyze_password", "3": "analyze_username",
            "4": "analyze_card",  "5": "analyze_iban",     "6": "analyze_crypto",
            "7": "analyze_cnic",  "8": "analyze_passport", "9": "analyze_phone",
            "10": "analyze_api_key",
        }
        if _choice in _MENU_MAP:
            return RouteDecision(primary=Module.CREDENTIAL,
                                 action=f"prompt_for_{_MENU_MAP[_choice]}", raw_text=text)
        if ent.emails:
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_email", entities=ent, raw_text=text)
        if ent.passwords:
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_password", entities=ent, raw_text=text)
        if ent.cards:
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_card", entities=ent, raw_text=text)
        if ent.ibans:
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_iban", entities=ent, raw_text=text)
        if ent.cnics:
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_cnic", entities=ent, raw_text=text)
        if ent.mrz_pairs:
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_passport", entities=ent, raw_text=text)
        if ent.crypto_addresses:
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_crypto", entities=ent, raw_text=text)
        if ent.crypto_private_keys:
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_private_key", entities=ent, raw_text=text)
        if ent.api_keys:
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_api_key", entities=ent, raw_text=text)
        if ent.phone_numbers:
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_phone", entities=ent, raw_text=text)
        return RouteDecision(primary=Module.CREDENTIAL, action="detect_and_analyze", entities=ent, raw_text=text)

    if state in ("AWAITING_PROFILE_DATA", "AWAITING_PROFILE_CONFIRM"):
        return RouteDecision(primary=Module.PROFILE, action="collect_data", entities=ent, raw_text=text)

    if state == "AWAITING_LINK_OFFER":
        if text_lower.strip() in {"yes","y","yeah","yep","sure","ok","okay","han","haan","1",
                                   "haan ji","haan bhai","yes please","go ahead","run it"}:
            return RouteDecision(primary=Module.PROFILE, action="from_social_url", entities=ent, raw_text=text)

    if state == "AWAITING_DEEPFAKE_CONFIRM":
        if text_lower in {"yes","y","yeah","yep","sure","ok","okay","han","haan","1",
                          "haan ji","yes please","go ahead"}:
            url = session.get("_pending_image_url", "")
            if url:
                return RouteDecision(primary=Module.DEEPFAKE, action="analyze_image_url", raw_text=url, context=url)
        return RouteDecision(primary=Module.SPECIAL, action="cancel", raw_text=text)

    # ── Pre-checks ────────────────────────────────────────────────────────────
    if _is_angry(text_lower):
        return RouteDecision(primary=Module.IRRELEVANT, action="angry_user", raw_text=text)
    if _is_jailbreak(text_lower):
        return RouteDecision(primary=Module.SPECIAL, action="jailbreak_block", raw_text=text)

    # ── WRONG-X intercept: fires before entity routing ────────────────────────
    # e.g. "check this email https://google.com" → deny, not link scan
    # e.g. "check my password test@gmail.com" → deny, not email disambig
    _wrong_x = _detect_wrong_x_in_text(text_lower, ent)
    if _wrong_x:
        return RouteDecision(primary=Module.SPECIAL, action="wrong_x_deny",
                             raw_text=text, context=_wrong_x)

    # FIX-001: Greeting check EARLY — before username extraction fires
    # Check if greeting is Urdu/Pakistani → serve Urdu help menu
    if _is_greeting(text_lower):
        _urdu_greetings = {
            "salam", "salaam", "assalam", "aoa", "assalamoalaikum",
            "assalamu alaikum", "assalamu", "walaikum", "walaikumsalam",
            "walaikum salam", "wa alaikum", "wa alaikum salam",
            "aslam o alaikum", "aslam", "aslamoalaikum",
            "salam bhai", "salam ji", "ji salam", "salam karo",
            "as salam", "assalamualaikum", "salam alaikum",
        }
        _is_urdu_greeting = (
            text_lower.strip() in _urdu_greetings
            or any(text_lower.strip().startswith(g) for g in _urdu_greetings)
            or _URDU_INDICATORS.search(text)
        )
        if _is_urdu_greeting:
            return RouteDecision(primary=Module.SPECIAL, action="urdu_help_menu", raw_text=text)
        return RouteDecision(primary=Module.SPECIAL, action="help_menu", raw_text=text)

    # FIX-007: Urdu/Roman Urdu — fire early; use _no_real_entities so short
    # English words accidentally extracted as usernames don't block this path.
    if _URDU_INDICATORS.search(text) or _ROMAN_URDU.search(text_lower):
        _no_cred_or_url = (
            not ent.urls and not ent.social_urls
            and not ent.emails and not ent.passwords and not ent.cards
            and not ent.cnics and not ent.ibans and not ent.api_keys
            and not ent.crypto_addresses and not ent.phone_numbers and not ent.handles
        )
        if _no_cred_or_url:
            return RouteDecision(primary=Module.IRRELEVANT, action="urdu_message", raw_text=text)

    # ── Follow-up check ───────────────────────────────────────────────────────
    # FIX-003: Use a tighter entity check — usernames extracted from short phrases
    # like "is it safe" or "is this ok" should NOT block follow-up detection.
    _no_real_entities = (
        not ent.urls and not ent.social_urls and not ent.emails
        and not ent.passwords and not ent.cards and not ent.cnics
        and not ent.ibans and not ent.api_keys and not ent.crypto_addresses
        and not ent.phone_numbers and not ent.handles
    )
    # For follow-up we also ignore plain usernames UNLESS the message is clearly
    # about a username (i.e. it has a @ prefix or is an explicit profile request)
    _is_followup_candidate = _no_real_entities and (
        not ent.usernames
        or len(text.split()) <= 8  # short messages can still be follow-ups even with extracted words
    )
    if last_scan and _is_followup_candidate:
        if any(kw in text_lower for kw in _FOLLOWUP_RESCAN):
            return RouteDecision(primary=Module.FOLLOWUP, action="rescan", raw_text=text, context=text)
        if any(kw in text_lower for kw in _FOLLOWUP_EXPLAIN):
            return RouteDecision(primary=Module.FOLLOWUP, action="explain", raw_text=text, context=text)
        if any(kw in text_lower for kw in _FOLLOWUP_ACTION):
            return RouteDecision(primary=Module.FOLLOWUP, action="action_advice", raw_text=text, context=text)

    # ── History / Clear ───────────────────────────────────────────────────────
    _no_url_cred = (not ent.urls and not ent.emails and not ent.passwords
                    and not ent.cards and not ent.api_keys and not ent.phone_numbers)
    if any(kw in text_lower for kw in _CLEAR_KEYWORDS) and _no_url_cred:
        return RouteDecision(primary=Module.SPECIAL, action="clear_session", raw_text=text)
    if any(kw in text_lower for kw in _HISTORY_KEYWORDS):
        return RouteDecision(primary=Module.SPECIAL, action="history", raw_text=text)

    # ── FIX: 'scan this profile X' with email/handle present → profile analysis ──
    _SCAN_PROFILE_EXPLICIT = {
        "scan this profile", "scan this account", "scan this user",
        "analyse this profile", "analyze this profile", "check this profile",
        "profile scan", "profile check", "analyse this account", "analyze this account",
    }
    if any(kw in text_lower for kw in _SCAN_PROFILE_EXPLICIT):
        if ent.emails:
            # Email provided with profile scan request → treat email as the subject
            new_d = RouteDecision(primary=Module.PROFILE, action="analyze",
                                  entities=ent, raw_text=text, context=text)
            return new_d
        if ent.handles or ent.social_urls or ent.usernames:
            return RouteDecision(primary=Module.PROFILE, action="analyze",
                                 entities=ent, raw_text=text, context=text)
        return RouteDecision(primary=Module.SPECIAL, action="prompt_for_profile", raw_text=text)

    # FIX-002: Image + text intent mismatch — check BEFORE default image routing
    if ent.has_image:
        _img_text = text_lower
        _wants_link = (
            any(kw in _img_text for kw in _MISSING_LINK_KEYWORDS)
            or (any(kw in _img_text for kw in _LINK_KEYWORDS) and not ent.urls and not ent.social_urls)
        )
        _wants_cred = (
            any(kw in _img_text for kw in _MISSING_CREDENTIAL_KEYWORDS)
            or (_has_cred_keywords(_img_text) and not ent.emails and not ent.passwords
                and not ent.cards and not ent.cnics and not ent.ibans
                and not ent.api_keys and not ent.crypto_addresses and not ent.phone_numbers)
        )
        _wants_profile = (
            any(kw in _img_text for kw in _MISSING_PROFILE_KEYWORDS)
            or (_has_keywords(_img_text, _PROFILE_KEYWORDS) and not ent.handles and not ent.social_urls)
        )
        if _wants_link and not _wants_cred:
            return RouteDecision(primary=Module.SPECIAL, action="image_but_wants_link", raw_text=text)
        if _wants_cred and not _wants_link:
            return RouteDecision(primary=Module.SPECIAL, action="image_but_wants_credential", raw_text=text)
        if _wants_profile and not _wants_link and not _wants_cred:
            return RouteDecision(primary=Module.SPECIAL, action="image_but_wants_profile", raw_text=text)

    # ── P5: Image routing — FIX-10 ───────────────────────────────────────────
    if ent.has_image:
        if any(kw in text_lower for kw in _QR_KEYWORDS):
            return RouteDecision(primary=Module.QR, action="scan", entities=ent, raw_text=text)
        if any(kw in text_lower for kw in _SCAN_FACE_KEYWORDS):
            return RouteDecision(primary=Module.DEEPFAKE, action="analyze_image", raw_text=text)
        if any(kw in text_lower for kw in _DEEPFAKE_KEYWORDS):
            return RouteDecision(primary=Module.DEEPFAKE, action="analyze_image", raw_text=text)
        return RouteDecision(primary=Module.QR, action="scan", entities=ent, raw_text=text)

    # FIX-003: Link-without-URL prompts — EARLY (before P1 commands)
    if not ent.urls and not ent.social_urls and not ent.has_image and not ent.has_video:
        if any(kw in text_lower for kw in _MISSING_LINK_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_link", raw_text=text)

    # FIX-C + FIX-10: Media text prompts (no image/video present)
    if not ent.has_image and not ent.has_video and not ent.urls and not ent.social_urls:
        if any(kw in text_lower for kw in _QR_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_qr_image", raw_text=text)
        if any(kw in text_lower for kw in _SCAN_VIDEO_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_deepfake_video", raw_text=text)
        if any(kw in text_lower for kw in _SCAN_FACE_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_deepfake_image_or_video", raw_text=text)
        if any(kw in text_lower for kw in _DEEPFAKE_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_deepfake_image", raw_text=text)
        if any(kw in text_lower for kw in _SCAN_IMAGE_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_any_image", raw_text=text)

    # ── P1: Explicit commands ─────────────────────────────────────────────────
    for cmd, (module, action) in _COMMANDS.items():
        if text_lower.startswith(cmd):
            remainder = text[len(cmd):].strip()
            if cmd == "/check" and remainder:
                from app.router.extractor import extract as _ext
                ent2 = _ext(remainder)
                if ent2.passwords or re.search(r"password[:\s]", remainder, re.I):
                    return RouteDecision(primary=Module.CREDENTIAL, action="analyze_password",
                                         entities=ent2, command=cmd, raw_text=text, context=text)
                if ent2.emails:
                    return RouteDecision(primary=Module.CREDENTIAL, action="analyze_email",
                                         entities=ent2, command=cmd, raw_text=text, context=text)
                if ent2.cards:
                    return RouteDecision(primary=Module.CREDENTIAL, action="analyze_card",
                                         entities=ent2, command=cmd, raw_text=text, context=text)
                if ent2.cnics:
                    return RouteDecision(primary=Module.CREDENTIAL, action="analyze_cnic",
                                         entities=ent2, command=cmd, raw_text=text, context=text)
                if ent2.ibans:
                    return RouteDecision(primary=Module.CREDENTIAL, action="analyze_iban",
                                         entities=ent2, command=cmd, raw_text=text, context=text)
                if ent2.api_keys:
                    return RouteDecision(primary=Module.CREDENTIAL, action="analyze_api_key",
                                         entities=ent2, command=cmd, raw_text=text, context=text)
                if ent2.crypto_addresses:
                    return RouteDecision(primary=Module.CREDENTIAL, action="analyze_crypto",
                                         entities=ent2, command=cmd, raw_text=text, context=text)
                if ent2.phone_numbers:
                    return RouteDecision(primary=Module.CREDENTIAL, action="analyze_phone",
                                         entities=ent2, command=cmd, raw_text=text, context=text)
                if re.search(r"username[:\s]", remainder, re.I):
                    uname_match = re.search(r"username[:\s]+([\S]+)", remainder, re.I)
                    uname_val = uname_match.group(1).lstrip("@") if uname_match else remainder
                    return RouteDecision(primary=Module.CREDENTIAL, action="analyze_username",
                                         entities=ent2, command=cmd, raw_text=uname_val, context=text)
            from app.router.extractor import extract as _ext
            ent2 = _ext(remainder) if remainder else ent
            return RouteDecision(primary=module, action=action, entities=ent2, command=cmd,
                                  raw_text=text, context=text)

    # Duplicate link-prompt (after commands)
    if not ent.urls and not ent.social_urls and not ent.has_image and not ent.has_video:
        if any(kw in text_lower for kw in _MISSING_LINK_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_link", raw_text=text)

    # ── Smishing fast-path ────────────────────────────────────────────────────
    # FIX-9: Run smishing BEFORE credential check.
    # Also intercept when URL is a shortener (bit.ly, tinyurl) inside smishing message.
    _has_real_cred_entities = (
        ent.emails or ent.passwords or ent.cards or ent.cnics
        or ent.ibans or ent.api_keys or ent.crypto_addresses
        or ent.phone_numbers or ent.handles or ent.social_urls
    )
    # Allow smishing with URLs if the URL is a shortener (common in smishing)
    _url_is_shortener = ent.urls and any(
        s in (ent.urls[0] if ent.urls else "") for s in ["bit.ly","tinyurl","goo.gl","t.co","ow.ly","rb.gy"]
    )
    if not _has_real_cred_entities and _looks_like_smishing(text_lower):
        return RouteDecision(primary=Module.CREDENTIAL, action="analyze_smishing",
                              entities=ent, raw_text=text, context=text)
    if _url_is_shortener and _looks_like_smishing(text_lower):
        return RouteDecision(primary=Module.CREDENTIAL, action="analyze_smishing",
                              entities=ent, raw_text=text, context=text)

    # ── Bot identity ─────────────────────────────────────────────────────────
    _WHO_KW_EARLY = {
        "what is aegis", "what is aegis ai", "about aegis", "aegis ai",
        "about this bot", "what is this service", "who are you",
        "what are you", "tell me about yourself", "introduce yourself",
        "who built you", "who made you", "who created you",
    }
    if any(kw in text_lower for kw in _WHO_KW_EARLY):
        return RouteDecision(primary=Module.IRRELEVANT, action="bot_who", raw_text=text)

    # ── Cyber Q&A ─────────────────────────────────────────────────────────────
    if _has_keywords(text_lower, _CYBER_QA_KEYWORDS):
        return RouteDecision(primary=Module.CYBER_QA, action="answer", raw_text=text, context=text)

    # ── P2: Profile ───────────────────────────────────────────────────────────
    if _has_keywords(text_lower, _PROFILE_KEYWORDS):
        if ent.handles or ent.social_urls:
            return RouteDecision(primary=Module.PROFILE, action="analyze", entities=ent,
                                  raw_text=text, context=text)
        if (not ent.handles and not ent.social_urls and
            any(w in text_lower for w in ["face","photo","picture","image"]) and
            not any(w in text_lower for w in ["trustworthy","trust","safe","scammer","real","fake","legit"])):
            # Only route to deepfake if explicitly asking about image/face content
            if "video" in text_lower or "clip" in text_lower:
                return RouteDecision(primary=Module.SPECIAL, action="prompt_for_deepfake_video", raw_text=text)
            elif any(w in text_lower for w in ["image","photo","picture"]):
                return RouteDecision(primary=Module.SPECIAL, action="prompt_for_deepfake_image", raw_text=text)
            else:
                return RouteDecision(primary=Module.SPECIAL, action="prompt_for_deepfake_media", raw_text=text)
        _PROFILE_COMMON = {
            "profile","account","this","that","check","verify","analyse","analyze",
            "real","fake","safe","user","person","name","tell","show","the","is",
            "it","he","she","their","them","his","her","look","seems","appears",
            "approaching","contacting","messaged","sent","shared",
        }
        if ent.usernames:
            _INLINE_SKIP = {
                "profile","account","this","that","check","verify","analyse","analyze",
                "real","fake","safe","user","person","name","tell","show","the","is",
                "it","he","she","their","them","his","her","look","seems","appears",
                "approaching","contacting","messaged","sent","shared","want","need",
                "does","did","use","let","say","try","see","ask","know","think",
            }
            real_unames = [u for u in ent.usernames
                           if u.lower() not in _PROFILE_COMMON
                           and u.lower() not in _INLINE_SKIP
                           and len(u) >= 4]
            if real_unames and not any([ent.emails, ent.passwords, ent.cards,
                                         ent.cnics, ent.ibans, ent.api_keys,
                                         ent.crypto_addresses, ent.phone_numbers]):
                return RouteDecision(primary=Module.PROFILE, action="analyze", entities=ent,
                                      raw_text=text, context=text)
        if not ent.handles and not ent.social_urls:
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_profile",
                                  raw_text=text, context=text)

    # ── P3: Link + URL ────────────────────────────────────────────────────────
    if _has_keywords(text_lower, _LINK_KEYWORDS) and (ent.urls or ent.social_urls):
        return RouteDecision(primary=Module.LINK, action="scan", entities=ent,
                              raw_text=text, context=text)

    # ── General menu ──────────────────────────────────────────────────────────
    if _has_keywords(text_lower, _GENERAL_MENU_KEYWORDS):
        return RouteDecision(primary=Module.SPECIAL, action="general_menu", raw_text=text)

    # ── P4: Credential keyword without entity ─────────────────────────────────
    _no_real_cred = (not ent.emails and not ent.urls and not ent.social_urls
                     and not ent.passwords and not ent.cards and not ent.ibans
                     and not ent.api_keys and not ent.crypto_addresses
                     and not ent.phone_numbers and not ent.cnics and not ent.handles)

    # FIX-2/4: Check specific credential-type intent FIRST (before generic menu)
    # These fire even when _has_cred_keywords doesn't match, catching "check my email" etc.
    if _no_real_cred and not _looks_like_smishing(text_lower):
        _WANTS_EMAIL  = {"check my email","check this email","is my email","my email leaked",
                         "email breach","email hacked","email in breach","email check",
                         "is my email breached","was my email hacked","is this email breached",
                         "is this email leaked","check email breach","email safe"}
        _WANTS_PHONE  = {"check my phone","check this phone","check phone number","phone breach",
                         "is my number","my phone leaked","phone number check","check my number",
                         "is my phone number","check this number","is this number breached",
                         "phone safe","is my phone safe"}
        _WANTS_PWD    = {"check my password","check this password","is my password","password safe",
                         "password strong","password check","test my password","is this password",
                         "my password","password strength","is it a strong password"}
        _WANTS_CNIC   = {"check my cnic","check this cnic","verify cnic","cnic check",
                         "is my cnic","my cnic","cnic valid","is this cnic valid"}
        _WANTS_CARD   = {"check my card","check this card","credit card check","card check",
                         "my card number","is my card","is this card valid"}
        _WANTS_IBAN   = {"check my iban","check this iban","verify iban","iban check",
                         "my iban","is my iban","is this iban valid"}
        _WANTS_CRYPTO = {"check crypto","check wallet","crypto address check","wallet check",
                         "check this wallet","bitcoin address check","ethereum address check",
                         "check this bitcoin","check this ethereum","is this wallet valid"}
        _WANTS_API    = {"check api key","check this api","api key check","token check",
                         "check my api key","check my token","is this api key valid",
                         "check this token","is this key valid","api key safe"}
        _WANTS_USER   = {"check username","check this username","username check",
                         "is this username breached","check my username"}

        for kw_set, prompt_action in [
            (_WANTS_EMAIL,  "prompt_for_analyze_email"),
            (_WANTS_PHONE,  "prompt_for_analyze_phone"),
            (_WANTS_PWD,    "prompt_for_analyze_password"),
            (_WANTS_CNIC,   "prompt_for_analyze_cnic"),
            (_WANTS_CARD,   "prompt_for_analyze_card"),
            (_WANTS_IBAN,   "prompt_for_analyze_iban"),
            (_WANTS_CRYPTO, "prompt_for_analyze_crypto"),
            (_WANTS_API,    "prompt_for_analyze_api_key"),
            (_WANTS_USER,   "prompt_for_analyze_username"),
        ]:
            if any(kw in text_lower for kw in kw_set):
                return RouteDecision(primary=Module.CREDENTIAL, action=prompt_action, raw_text=text)

    # Don't trigger credential menu for smishing messages — they're already handled above
    if _has_cred_keywords(text_lower) and _no_real_cred and not _looks_like_smishing(text_lower):
        return RouteDecision(primary=Module.SPECIAL, action="prompt_credential", raw_text=text)

    # ── P6/P7: Video / Image ──────────────────────────────────────────────────
    if ent.has_video:
        if any(kw in text_lower for kw in _QR_KEYWORDS):
            return RouteDecision(primary=Module.QR, action="scan_video", entities=ent, raw_text=text)
        if any(kw in text_lower for kw in _SCAN_FACE_KEYWORDS | _DEEPFAKE_KEYWORDS | _SCAN_VIDEO_KEYWORDS):
            return RouteDecision(primary=Module.DEEPFAKE, action="analyze_video", raw_text=text)
        return RouteDecision(primary=Module.QR, action="scan_video", entities=ent, raw_text=text)

    if ent.has_image:
        if any(kw in text_lower for kw in _QR_KEYWORDS):
            return RouteDecision(primary=Module.QR, action="scan", entities=ent, raw_text=text)
        if any(kw in text_lower for kw in _SCAN_FACE_KEYWORDS | _DEEPFAKE_KEYWORDS):
            return RouteDecision(primary=Module.DEEPFAKE, action="analyze_image", raw_text=text)
        return RouteDecision(primary=Module.QR, action="scan", entities=ent, raw_text=text)

    if not ent.has_image and not ent.has_video and not ent.has_any():
        if any(kw in text_lower for kw in _QR_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_qr_image", raw_text=text)
        if any(kw in text_lower for kw in _SCAN_VIDEO_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_deepfake_video", raw_text=text)
        if any(kw in text_lower for kw in _SCAN_FACE_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_deepfake_image_or_video", raw_text=text)
        if any(kw in text_lower for kw in _DEEPFAKE_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_deepfake_image", raw_text=text)
        if any(kw in text_lower for kw in _SCAN_IMAGE_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_any_image", raw_text=text)
        if any(kw in text_lower for kw in _VIDEO_KEYWORDS):
            return RouteDecision(primary=Module.SPECIAL, action="prompt_for_any_video", raw_text=text)

    if ent.has_audio:
        return RouteDecision(primary=Module.IRRELEVANT, action="no_voice", raw_text=text)

    # ── P8: @handle ───────────────────────────────────────────────────────────
    if ent.handles:
        return RouteDecision(primary=Module.PROFILE, secondary=Module.CREDENTIAL,
                              action="analyze_handle", entities=ent, raw_text=text, context=text)

    # ── P9: Social URL ────────────────────────────────────────────────────────
    if ent.social_urls:
        if ent.urls:
            return _build_multi_route(ent, text)
        return RouteDecision(primary=Module.LINK, secondary=Module.PROFILE,
                              action="social_url_dual", entities=ent, raw_text=text, context=text)

    # ── P10: URLs ─────────────────────────────────────────────────────────────
    if ent.urls:
        raw_stripped = text.strip()
        has_explicit_scheme = (raw_stripped.lower().startswith("http://")
                               or raw_stripped.lower().startswith("https://")
                               or raw_stripped.lower().startswith("www."))
        url_is_bare = (len(ent.urls) == 1 and not has_explicit_scheme
                       and not ent.social_urls and "." in raw_stripped
                       and "/" not in raw_stripped and " " not in raw_stripped)
        if url_is_bare:
            username_part = raw_stripped.split(".")[0]
            return RouteDecision(
                primary=Module.SPECIAL, action="disambiguate", needs_disambig=True,
                disambig_opts={
                    "1": ("link",    raw_stripped,  "🔗 Link Safety Check"),
                    "2": ("profile", username_part, "👤 Profile Analysis"),
                    "3": ("both",    username_part, "🔍 Run All"),
                },
                entities=ent, raw_text=text,
            )
        if len(ent.urls) > 1:
            return RouteDecision(primary=Module.LINK, action="bulk_scan", entities=ent,
                                  raw_text=text, context=text)
        if ent.api_keys:
            return RouteDecision(
                primary=Module.MULTI,
                concurrent_routes=[
                    RouteDecision(primary=Module.LINK, action="scan", entities=ent, raw_text=text, context=text),
                    RouteDecision(primary=Module.CREDENTIAL, action="analyze_api_key", entities=ent, raw_text=text),
                ],
                raw_text=text, context=text,
            )
        return RouteDecision(primary=Module.LINK, action="scan", entities=ent,
                              raw_text=text, context=text)

    # ── P11: Credential patterns ──────────────────────────────────────────────
    cred = _classify_credential(ent, text, text_lower)
    if cred:
        cred.context = text
        return cred

    # ── P12: Cyber Q&A catch-all ──────────────────────────────────────────────
    if _looks_like_question(text_lower) and any(
            w in text_lower for w in ["cyber","security","hack","safe","scam",
                                       "fraud","phish","malware","virus","vpn"]):
        return RouteDecision(primary=Module.CYBER_QA, action="answer", raw_text=text, context=text)

    # ── P13: Plain username ───────────────────────────────────────────────────
    _has_real_entities = (
        bool(ent.emails) or bool(ent.urls) or bool(ent.social_urls)
        or bool(ent.passwords) or bool(ent.cards) or bool(ent.ibans)
        or bool(ent.api_keys) or bool(ent.crypto_addresses)
        or bool(ent.phone_numbers) or bool(ent.cnics) or bool(ent.handles)
    )
    if ent.usernames and not _has_real_entities:
        username_candidate = ent.usernames[0].lower()
        stripped = text.strip()
        _is_likely_username_msg = (
            len(stripped.split()) <= 3
            and len(stripped) <= 60
            and (stripped.endswith(username_candidate) or stripped == username_candidate
                 or (len(stripped.split()) == 1))
        )
        _SKIP_WORDS = {
            "want","check","email","scan","link","the","and","for","you","your",
            "this","that","what","with","from","have","been","will","are","not",
            "can","some","into","than","they","them","then","also","more","about",
            "just","know","user","good","like","time","very","when","come","here",
            "how","its","our","out","who","get","may","his","her","him","she",
            "was","had","has","look","help","real","fake","safe","risk","bad",
            "send","please","does","did","use","let","say","try","see","ask",
            "weather","today","service","totally","useless","problem","issue",
            "tell","show","give","make","take","keep","open","close","find",
            "read","write","move","stop","start","play","pass","turn","work",
            "mean","know","need","feel","seem","become","call","once","done",
            "image","whats","salam","salaam","hello","bhai","aoa","haan",
        }
        if (username_candidate not in _SKIP_WORDS
                and len(username_candidate) >= 4
                and _is_likely_username_msg):
            return _disambiguation_3opt(ent.usernames[0], ent, text)

    stripped = text.strip()
    bare_domain = re.match(r"^([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]?\.[a-z]{2,})$", stripped.lower())
    if bare_domain:
        username_part = stripped.split(".")[0]
        return RouteDecision(
            primary=Module.SPECIAL, action="disambiguate", needs_disambig=True,
            disambig_opts={
                "1": ("link",       stripped, f"🔗 Scan as URL — check if {stripped} is safe to visit"),
                "2": ("profile",    username_part, f"👤 Analyse @{username_part} as a social media profile"),
                "3": ("credential", username_part, f"🔑 Check '{username_part}' as a username credential"),
            },
            entities=ent, raw_text=text,
        )

    # ── P14 ───────────────────────────────────────────────────────────────────
    if any(kw in text_lower for kw in _GENERAL_MENU_KEYWORDS):
        return RouteDecision(primary=Module.SPECIAL, action="general_menu", raw_text=text)

    _WHO_KEYWORDS = {
        "who are you","what are you","what is aegis","tell me about yourself",
        "about you","who made you","what is your purpose","are you a bot","are you ai",
        "who built you","who created you","what is this","introduce yourself",
        "about aegis","aegis ai","what is this bot","tell me about aegis",
        "what is aegis ai","about aegis ai","aegis ai kya hai",
        "what is this service","tell me about this service",
    }
    if any(kw in text_lower for kw in _WHO_KEYWORDS):
        return RouteDecision(primary=Module.IRRELEVANT, action="bot_who", raw_text=text)

    if _is_greeting(text_lower):
        return RouteDecision(primary=Module.SPECIAL, action="help_menu", raw_text=text)
    if _URDU_INDICATORS.search(text) or _ROMAN_URDU.search(text_lower):
        return RouteDecision(primary=Module.IRRELEVANT, action="urdu_message", raw_text=text)
    if _is_emoji_only(text):
        return RouteDecision(primary=Module.IRRELEVANT, action="emoji_only", raw_text=text)
    if _is_gibberish(text):
        return RouteDecision(primary=Module.IRRELEVANT, action="gibberish", raw_text=text)

    return RouteDecision(primary=Module.IRRELEVANT, action="off_topic", raw_text=text)


# ============================================================================
# Credential sub-classifier
# ============================================================================

def _classify_credential(ent: ExtractedEntities, text: str, text_lower: str) -> Optional[RouteDecision]:
    if ent.emails and ent.passwords:
        real_passwords = [p for p in ent.passwords if p.lower() not in [e.lower() for e in ent.emails]]
        if real_passwords:
            return RouteDecision(primary=Module.MULTI, concurrent_routes=[
                RouteDecision(primary=Module.CREDENTIAL, action="analyze_email", entities=ent, raw_text=text),
                RouteDecision(primary=Module.CREDENTIAL, action="analyze_password", entities=ent, raw_text=text),
            ], raw_text=text)
        return RouteDecision(primary=Module.SPECIAL, action="disambiguate", needs_disambig=True,
            disambig_opts={
                "1": ("credential_email", ent.emails[0], "🔑 Leak Monitor"),
                "2": ("profile_email",    ent.emails[0], "👤 Scam Check"),
                "3": ("both_email",       ent.emails[0], "🔍 Run Both"),
            },
            entities=ent, raw_text=text)

    entity_count = sum(bool(x) for x in [
        ent.emails, ent.passwords, ent.cards, ent.ibans,
        ent.cnics, ent.api_keys, ent.crypto_addresses, ent.phone_numbers,
    ])
    if entity_count >= 2:
        return RouteDecision(primary=Module.CREDENTIAL, action="bulk_detect", entities=ent, raw_text=text)

    if ent.crypto_private_keys:
        return RouteDecision(primary=Module.CREDENTIAL, action="analyze_private_key", entities=ent, raw_text=text)
    if ent.api_keys:
        return RouteDecision(primary=Module.CREDENTIAL, action="analyze_api_key", entities=ent, raw_text=text)
    if ent.mrz_pairs:
        return RouteDecision(primary=Module.CREDENTIAL, action="analyze_passport", entities=ent, raw_text=text)
    if ent.cnics:
        return RouteDecision(primary=Module.CREDENTIAL, action="analyze_cnic", entities=ent, raw_text=text)
    if ent.ibans:
        return RouteDecision(primary=Module.CREDENTIAL, action="analyze_iban", entities=ent, raw_text=text)
    if ent.cards:
        return RouteDecision(primary=Module.CREDENTIAL, action="analyze_card", entities=ent, raw_text=text)
    if ent.crypto_addresses:
        return RouteDecision(primary=Module.CREDENTIAL, action="analyze_crypto", entities=ent, raw_text=text)
    if ent.passwords:
        return RouteDecision(primary=Module.CREDENTIAL, action="analyze_password", entities=ent, raw_text=text)
    if ent.emails:
        return RouteDecision(primary=Module.SPECIAL, action="disambiguate", needs_disambig=True,
            disambig_opts={
                "1": ("credential_email", ent.emails[0], "🔑 Leak Monitor"),
                "2": ("profile_email",    ent.emails[0], "👤 Scam Check"),
                "3": ("both_email",       ent.emails[0], "🔍 Run Both"),
            },
            entities=ent, raw_text=text)
    if ent.phone_numbers:
        non_phone = text_lower
        for p in ent.phone_numbers:
            non_phone = non_phone.replace(p.lower().replace("+",""), "")
        if ent.raw_text_for_smishing and _looks_like_smishing(non_phone):
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_smishing", entities=ent, raw_text=text)
        return RouteDecision(primary=Module.SPECIAL, action="disambiguate", needs_disambig=True,
            disambig_opts={
                "1": ("credential_phone", ent.phone_numbers[0], "🔑 Leak Monitor"),
                "2": ("profile_phone",    ent.phone_numbers[0], "👤 Scam Check"),
                "3": ("both_phone",       ent.phone_numbers[0], "🔍 Run Both"),
            },
            entities=ent, raw_text=text)

    if _looks_like_smishing(text_lower):
        return RouteDecision(primary=Module.CREDENTIAL, action="analyze_smishing", entities=ent, raw_text=text)
    return None


# ── Disambiguation helpers ────────────────────────────────────────────────────

def _disambiguation_3opt(username: str, ent: ExtractedEntities, text: str) -> RouteDecision:
    return RouteDecision(
        primary=Module.SPECIAL, action="disambiguate", needs_disambig=True,
        disambig_opts={
            "1": ("password", username, "🔐 Password Check"),
            "2": ("profile",  username, "👤 Profile Analysis"),
            "3": ("both",     username, "🔍 Run Both"),
        },
        entities=ent, raw_text=text,
    )


def _handle_disambiguation_response(text_lower: str, session: dict) -> RouteDecision:
    opts   = session.get("disambiguation_options", {})
    choice = text_lower.strip()
    if choice in opts:
        module_name, entity, _ = opts[choice]
        if module_name == "both":
            domain = session.get("_disambig_entity", "") or entity
            # For usernames: credential check + profile analysis in parallel
            # For domains: link scan + profile analysis in parallel
            is_domain = "." in domain and "/" not in domain and "@" not in domain and len(domain.split(".")[0]) > 2
            if is_domain:
                return RouteDecision(primary=Module.MULTI, concurrent_routes=[
                    RouteDecision(primary=Module.LINK, action="scan", raw_text=domain),
                    RouteDecision(primary=Module.PROFILE, action="analyze_handle", raw_text=entity),
                ], raw_text=domain, action="from_disambiguation")
            else:
                # Username: run credential check + profile in parallel
                return RouteDecision(primary=Module.MULTI, concurrent_routes=[
                    RouteDecision(primary=Module.CREDENTIAL, action="analyze_username", raw_text=entity),
                    RouteDecision(primary=Module.PROFILE, action="analyze_handle", raw_text=entity),
                ], raw_text=entity, action="from_disambiguation")
        if module_name == "credential_email":
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_email", raw_text=entity)
        if module_name == "profile_email":
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_email",
                                  raw_text=entity, context="scam_check_email")
        if module_name == "both_email":
            return RouteDecision(primary=Module.SPECIAL, action="from_disambiguation",
                                  raw_text=entity, context="both_email")
        if module_name == "credential_phone":
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_phone", raw_text=entity)
        if module_name == "profile_phone":
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_phone",
                                  raw_text=entity, context="scam_check_phone")
        if module_name == "both_phone":
            return RouteDecision(primary=Module.SPECIAL, action="from_disambiguation",
                                  raw_text=entity, context="both_phone")
        if module_name in ("password", "password_check"):
            return RouteDecision(primary=Module.CREDENTIAL, action="analyze_password", raw_text=entity)
        if module_name == "link":
            from app.router.extractor import extract as _ext
            ent2 = _ext(entity)
            return RouteDecision(primary=Module.LINK, action="scan", entities=ent2, raw_text=entity)
        if module_name == "profile":
            return RouteDecision(primary=Module.PROFILE, action="analyze_handle", raw_text=entity)
        module = Module(module_name) if module_name in [m.value for m in Module] else Module.CREDENTIAL
        return RouteDecision(primary=module, action="from_disambiguation", raw_text=entity)
    return RouteDecision(primary=Module.SPECIAL, action="disambiguate_retry", raw_text=text_lower)


def _reclassify_escaped(text: str, ent: ExtractedEntities, session: dict) -> RouteDecision:
    clean_session = {k: v for k, v in session.items() if k != "state"}
    clean_session["state"] = "IDLE"
    return classify(text, ent, clean_session)


def _build_multi_route(ent: ExtractedEntities, text: str) -> RouteDecision:
    routes = []
    if ent.urls:
        routes.append(RouteDecision(primary=Module.LINK, action="bulk_scan", entities=ent, raw_text=text))
    if ent.social_urls:
        routes.append(RouteDecision(primary=Module.LINK, action="social_url_dual", entities=ent, raw_text=text))
    return RouteDecision(primary=Module.MULTI, concurrent_routes=routes, raw_text=text)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _has_keywords(text: str, keywords: set) -> bool:
    for kw in keywords:
        if kw in text:
            return True
    return False


def _has_cred_keywords(text: str) -> bool:
    import re as _re
    for kw in _CREDENTIAL_KEYWORDS:
        kw_stripped = kw.strip()
        if len(kw_stripped) <= 6:
            if _re.search(r'\b' + _re.escape(kw_stripped) + r'\b', text):
                return True
        else:
            if kw_stripped in text:
                return True
    return False


def _detect_wrong_x_in_text(text_lower: str, ent: "ExtractedEntities") -> str:
    """
    Detect wrong-X patterns purely from text keywords + extracted entities.
    Returns a denial message string if wrong-X detected, else empty string.
    Called BEFORE entity routing so e.g. 'check this email https://url' is caught.
    """
    # "check this email" + URL present (not email)
    _wants_email = any(kw in text_lower for kw in {
        "check this email","check my email","is this email","is my email",
        "email breach","email hacked","email leaked","email check",
    })
    if _wants_email and ent.urls and not ent.emails:
        return ("🔗 That's a *link*, not an email address.\n\n"
                "• To scan this link → just send the URL\n"
                "• To check an email for breaches → send the email address (e.g. `test@gmail.com`)")

    # "check this email" + CNIC present
    if _wants_email and ent.cnics and not ent.emails:
        return ("🪪 That's a *CNIC number*, not an email address.\n\n"
                "Please send the *email address* you want to check (e.g. `test@gmail.com`)")

    # "check my password" + email present
    _wants_pwd = any(kw in text_lower for kw in {
        "check my password","check this password","is my password","is this password",
        "password check","password strength","password strong","password weak",
    })
    if _wants_pwd and ent.emails and not ent.passwords:
        return ("📧 That's an *email address*, not a password.\n\n"
                "• To check the email for breaches → just send `" + (ent.emails[0] if ent.emails else "the email") + "`\n"
                "• To check a *password* → send just the password text\n\n"
                "Which would you like?")

    # "check this phone" + URL present
    _wants_phone = any(kw in text_lower for kw in {
        "check this phone","check my phone","check this number","check my number",
        "is this phone","is this number","phone check","number check",
        "is my number","is my phone",
    })
    if _wants_phone and ent.urls and not ent.phone_numbers:
        return ("🔗 That's a *link*, not a phone number.\n\n"
                "• To scan this link → just send the URL\n"
                "• To check a phone number → send the number (e.g. `+923001234567`)")

    # "check this phone" + email present
    if _wants_phone and ent.emails and not ent.phone_numbers:
        return ("📧 That's an *email address*, not a phone number.\n\n"
                "• To check an email → just send it\n"
                "• To check a phone number → send the number (e.g. `+923001234567`)")

    # "scan this qr" + text entity present (no image)
    _wants_qr = any(kw in text_lower for kw in {
        "scan this qr","scan qr","check this qr","qr code check","check qr",
    })
    if _wants_qr and (ent.urls or ent.emails or ent.cnics or ent.phone_numbers) and not ent.has_image:
        return ("📷 You asked to scan a *QR code*, but you sent text.\n\n"
                "Please send a *QR code image* — take a photo or screenshot of the QR code "
                "and send it here directly.")

    return ""


def _is_greeting(text: str) -> bool:
    words    = text.strip().split()
    if not words:
        return False
    first    = words[0].lower()
    full     = text.strip().lower()
    if first in _GREETING_WORDS:
        return True
    if full in _GREETING_WORDS:
        return True
    if len(words) <= 3 and first in _GREETING_WORDS:
        return True
    for gw in _GREETING_WORDS:
        if full.startswith(gw) and len(full) <= len(gw) + 10:
            return True
    return False


def _is_jailbreak(text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in _JAILBREAK_PATTERNS)


def _is_emoji_only(text: str) -> bool:
    stripped = re.sub(r"[\s\U0001F000-\U0001FFFF\U00002600-\U000027FF]", "", text)
    return len(stripped) == 0 and len(text.strip()) > 0


def _is_gibberish(text: str) -> bool:
    words = text.strip().split()
    if not words: return False
    alpha = sum(1 for w in words if re.match(r"[A-Za-z0-9]", w))
    return len(text) > 3 and alpha / max(len(words), 1) < 0.3


def _is_angry(text: str) -> bool:
    import re as _re
    words = {_re.sub(r"[^a-z]", "", w.lower()) for w in text.split()}
    return bool(words & _ANGRY_WORDS)


def _looks_like_question(text: str) -> bool:
    return text.strip().endswith("?") or text.lower().startswith(("what","how","why","is ","can "))


def _looks_like_smishing(text: str) -> bool:
    """
    FIX-9: Better smishing detection.
    - NADRA/CNIC expired → smishing (government impersonation)
    - 'Your OTP is 123456. Do not share' → SAFE (legitimate OTP)
    - 'Meeting at 3pm' → NOT smishing
    Returns True only for suspicious messages.
    """
    t = text.lower()

    # FIX-9a: Safe patterns — legitimate OTPs, bank confirmations, meeting reminders
    _SAFE = [
        r"your otp is\s+\d{4,8}",
        r"verification code[:  ]*\d{4,8}",
        r"do not share this code",
        r"your \d{4,6} is your otp",
        r"one.time.password",
        r"transaction.*successful",
        r"meeting.*confirmed",
        r"appointment.*confirmed",
        r"your order.*shipped",
        r"delivery.*scheduled",
        r"your booking.*confirmed",
        r"thank you for your.*payment",
    ]
    import re as _re
    for sp in _SAFE:
        if _re.search(sp, t, _re.IGNORECASE):
            return False

    # FIX-9b: High-confidence smishing signals — 1 hit = smishing
    _HIGH = {
        "dear customer", "dear sir", "dear madam", "dear user",
        "click here to claim", "click the link to", "click to verify",
        "your account has been suspended", "account will be suspended",
        "account has been blocked", "account blocked immediately",
        "you have won", "you have been selected", "congratulations you won",
        "claim your prize", "collect your reward", "claim now",
        "send your cnic", "share your cnic", "provide your cnic",
        "share your otp", "send your otp", "provide your otp",
        "send your pin", "share your pin",
        "your sim will be blocked", "your number will be deactivated",
        "jazzcash account blocked", "easypaisa account blocked",
    }
    for h in _HIGH:
        if h in t:
            return True

    # FIX-9c: Government impersonation (NADRA, FIA, PTCL, etc.) + action verb
    _GOV = {"nadra", "fia", "ptcl", "pta", "fbr", "government", "ministry"}
    _ACTION = {"visit", "call", "verify", "confirm", "update", "provide",
               "submit", "blocked", "suspended", "expired", "cancel"}
    has_gov = any(g in t for g in _GOV)
    has_action = any(a in t for a in _ACTION)
    if has_gov and has_action:
        return True

    # FIX-9d: Standard multi-keyword scoring — REQUIRE context (not just 2 bare words)
    smish = {
        "otp", "pin", "account blocked", "urgent", "click",
        "jazzcash", "easypaisa", "jazz", "hbl", "bank", "send money",
        "prize", "win", "winner", "reward", "claim",
        "suspended", "asap", "cnic", "bank account",
        "congratulations", "lottery", "limited time",
        "rs.", "pkr", "rupees", "amount",
        "bit.ly", "tinyurl", "goo.gl",
        "free", "offer", "discount", "gift",
    }
    # "verify" alone is too generic — only count it if paired with financial/account keywords
    _VERIFY_CONTEXT = {"otp","pin","account","cnic","number","sim","card","iban","bank","id"}
    if "verify" in t:
        if any(vc in t for vc in _VERIFY_CONTEXT):
            hits = sum(1 for kw in smish if kw in t) + 1  # count verify as a hit
        else:
            hits = sum(1 for kw in smish if kw in t)
    else:
        hits = sum(1 for kw in smish if kw in t)

    # Short standalone commands like "verify cnic", "check cnic" are NOT smishing
    _SAFE_COMMANDS = {
        "verify cnic", "check cnic", "cnic check", "verify passport",
        "check iban", "verify iban", "check password", "verify email",
    }
    if any(sc in t for sc in _SAFE_COMMANDS):
        return False

    return hits >= 2
