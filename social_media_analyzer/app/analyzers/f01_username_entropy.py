"""F-01: Username entropy + pattern analysis. Max 30 pts."""
import re, math, logging
from typing import List, Tuple
from app.models import UsernameEntropyResult

logger = logging.getLogger(__name__)
FAMOUS = ["elonmusk","justinbieber","cristiano","neymarjr","leomessi","kimkardashian",
          "therock","arianagrande","taylorswift","selenagomez","beyonce","kanyewest",
          "billgates","barackobama","narendramodi","imrankhan","realdonaldtrump"]

def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c,0)+1
    n = len(s)
    return -sum((f/n)*math.log2(f/n) for f in freq.values())

def analyze_username_entropy(username: str) -> UsernameEntropyResult:
    if not username:
        return UsernameEntropyResult(entropy_score=0,pattern_flags=["empty_username"],
            suspicion_points=10,details={})
    u = username.lower()
    entropy = shannon_entropy(u)
    pts = 0; flags: List[str] = []

    # High Shannon entropy → random-looking
    if entropy > 3.5: pts += 12; flags.append("high_entropy_random_looking")
    elif entropy > 3.0: pts += 6; flags.append("medium_entropy")

    # Trailing digits
    if re.search(r'\d{4,}$', u): pts += 8; flags.append("many_trailing_digits")
    elif re.search(r'\d{2,}$', u): pts += 4; flags.append("trailing_digits")

    # All numeric
    if u.isdigit(): pts += 12; flags.append("all_numeric_username")

    # Random consonant clusters
    if re.search(r'[bcdfghjklmnpqrstvwxyz]{5,}', u): pts += 8; flags.append("consonant_cluster")

    # Impersonation: leet-speak of famous name
    leet = u.translate(str.maketrans("0134567","oieasst"))
    for name in FAMOUS:
        if name in leet and name != u:
            pts += 20; flags.append(f"impersonation_lookalike:{name}"); break

    # Celebrity exact match → less suspicious
    if u in FAMOUS: pts = max(0, pts-10)

    # Underscore spam
    if u.count("_") >= 3: pts += 5; flags.append("excessive_underscores")

    # Very short
    if len(u) <= 2: pts += 5; flags.append("very_short_username")

    pts = min(pts, 30)
    logger.info(f"[F-01] @{username}: entropy={entropy:.2f} pts={pts} flags={flags}")
    return UsernameEntropyResult(entropy_score=round(entropy,3), pattern_flags=flags,
        suspicion_points=pts, details={"length":len(username),"is_numeric":u.isdigit()})
