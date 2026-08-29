"""F-02: Username vs display name divergence. Max 20 pts."""
import re, logging
from typing import Optional
from Levenshtein import ratio
from app.models import NameDivergenceResult

logger = logging.getLogger(__name__)
SCAM_KEYWORDS = ["guaranteed","profit","forex","crypto signal","investment","passive income",
                 "free bitcoin","giveaway","official","verified ceo","double your","airdrop",
                 "100%","dm me","whatsapp","telegram","helpdesk","support team","admin"]

def _clean(s: str) -> str:
    return re.sub(r"[^a-z0-9]","",s.lower())

def analyze_name_divergence(username: str, display_name: Optional[str]) -> NameDivergenceResult:
    if not display_name:
        return NameDivergenceResult(similarity_ratio=1.0, divergence_flag=False,
            suspicion_points=0, details={"note":"no display name"})
    sim = ratio(_clean(username), _clean(display_name))
    pts = 0; flag = False
    dn_lower = display_name.lower()
    scam_hits = [kw for kw in SCAM_KEYWORDS if kw in dn_lower]
    if scam_hits: pts += min(20, len(scam_hits)*7); flag = True
    elif sim < 0.3 and len(username) > 3: pts += 10; flag = True
    elif sim < 0.5: pts += 5
    pts = min(pts, 20)
    logger.info(f"[F-02] sim={sim:.2f} scam={scam_hits} pts={pts}")
    return NameDivergenceResult(similarity_ratio=round(sim,3), divergence_flag=flag,
        suspicion_points=pts, details={"scam_keywords_found":scam_hits,"username":username,"display_name":display_name})
