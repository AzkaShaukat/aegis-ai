"""F-13: Bio NLP scam classifier (no API key). Max 25 pts."""
import re, logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

SCAM_CATS: Dict[str, tuple] = {
    "financial":  (["guaranteed profit","guaranteed returns","passive income","forex signal",
                    "crypto signal","double your","triple your","500%","1000%","100% profit",
                    "risk free","daily returns","binary option","airdrop","free bitcoin",
                    "free crypto","free usdt","send and get back","investment opportunity"], 20),
    "urgency":    (["limited slots","limited spots","only today","hurry up","last chance",
                    "act now","expires soon","24 hours only","selling out","don't miss"], 15),
    "impersonation": (["official account","real account","not a scam","ceo of","founder of",
                        "endorsed by","affiliated with","verified by","team member","partnered with"], 15),
    "giveaway":   (["giveaway","give away","send 0.1 get 1","send btc get back","multiplied back",
                    "smart contract giveaway","free giveaway","win free"], 18),
    "dm_solicit": (["dm me","dm for","inbox me","message me for","whatsapp me","telegram me",
                    "contact for investment","private group","join my channel"], 12),
}
EMOJI_RE  = re.compile(r"[\U00010000-\U0010ffff]|[\U0001F300-\U0001FAFF]", flags=re.UNICODE)
LINK_RE   = re.compile(r"(t\.me/|wa\.link/|bit\.ly/|tinyurl|linktr\.ee|s\.id/)", re.I)
PHONE_RE  = re.compile(r"\+?\d[\d\s\-\(\)]{7,}\d")
CLAIM_RE  = re.compile(r"\b(official|admin|support|verified|helpdesk|moderator|authorized|certified)\b", re.I)
CAPS_RE   = re.compile(r"\b[A-Z]{4,}\b")

def analyze_bio_nlp(bio: str, display_name: str = "") -> Dict[str, Any]:
    if not bio and not display_name:
        return {"suspicion_points":0,"flags":[],"details":{"note":"no bio"}}
    full = f"{bio} {display_name}".lower()
    pts = 0; flags: List[str] = []; evidence: Dict[str,Any] = {}
    for cat, (terms, max_pts) in SCAM_CATS.items():
        hits = [t for t in terms if t in full]
        if hits:
            contribution = min(max_pts, len(hits)*7)
            evidence[cat] = {"terms":hits[:4],"pts":contribution}
            pts += contribution; flags.append(f"scam:{cat}")
    emojis = EMOJI_RE.findall(bio or "")
    if len(emojis) >= 4: pts += min(8, len(emojis)*2); flags.append(f"emoji_density:{len(emojis)}")
    if LINK_RE.search(bio or ""): pts += 8; flags.append("suspicious_link")
    if PHONE_RE.search(bio or ""): pts += 5; flags.append("phone_in_bio")
    claims = CLAIM_RE.findall(bio or "")
    if len(claims) >= 2: pts += 8; flags.append(f"authority_claims:{claims[:3]}")
    caps = CAPS_RE.findall(bio or "")
    if len(caps) >= 3: pts += 4; flags.append(f"excessive_caps:{caps[:3]}")
    pts = min(pts, 25)
    logger.info(f"[F-13] Bio NLP: {len(flags)} flags → pts={pts}")
    return {"suspicion_points":pts,"flags":flags,
            "details":{"evidence":evidence,"emoji_count":len(emojis),"bio_length":len(bio or "")}}
