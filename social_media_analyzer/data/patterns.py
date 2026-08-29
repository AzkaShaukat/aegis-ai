"""Aegis AI — All keyword lists, regex patterns, and reference data."""
import re

# ── Bio scam keyword categories ──────────────────────────────────────────────
BIO_SCAM_CATEGORIES = {
    "financial": [
        "forex", "trading signals", "guaranteed profit", "daily profit",
        "passive income", "binary options", "investment expert", "fund manager",
        "crypto trader", "100% profit", "risk free", "double your money",
        "make money online", "earn daily", "financial freedom", "get rich",
        "millionaire mindset", "money mentor", "profit daily", "trade signals",
        "investment tips", "high returns", "guaranteed returns", "earn from home",
        "side hustle", "financial advisor", "wealth manager", "stock tips",
        "options trader", "day trader", "pip master", "signal provider",
        "10x your money", "insider tips", "hot picks",
    ],
    "urgency": [
        "limited slots", "act now", "last chance", "hurry", "don't miss",
        "limited time", "24 hours", "spots left", "ending soon", "today only",
        "urgent", "immediately", "right now", "asap", "closing soon",
        "only 5 left", "first come", "time sensitive", "expires tonight",
        "last few spots", "doors closing", "grab your slot",
    ],
    "impersonation": [
        "official account", "verified by", "certified by", "authorized by",
        "government official", "minister", "prime minister", "ceo of",
        "founder of", "director of", "verified trader", "certified trader",
        "official page", "real account", "authentic account", "i am the real",
        "original account", "this is the real",
    ],
    "giveaway": [
        "send crypto get back", "double your btc", "send eth",
        "crypto giveaway", "bitcoin giveaway", "free crypto",
        "smart contract giveaway", "send usdt", "send trx",
        "matching funds", "i will match", "to receive", "send 0.1",
        "send 0.5", "100% legit giveaway", "verified giveaway",
        "participate now", "claim your",
    ],
    "dm_solicit": [
        "dm me", "message me", "inbox me", "dm for info",
        "whatsapp me", "join my channel", "join my group",
        "join telegram", "contact me privately", "reach me on",
        "slide into dm", "dm for details", "dm to invest",
        "link in bio", "click link", "t.me/", "wa.me/",
    ],
    "romance": [
        "looking for love", "single and ready", "find your soulmate",
        "lonely heart", "seeking relationship", "love companion",
        "travel companion wanted", "military on deployment",
        "widower seeking", "i am a doctor abroad",
        "working offshore", "un peacekeeper",
    ],
}

# ── Pakistani-specific scam patterns ─────────────────────────────────────────
PK_SCAM_PATTERNS = {
    "pk_gov_impersonation": [
        "nadra", "fbr", "fia", "nab", "pra", "secp",
        "state bank", "ministry of", "government of pakistan",
        "prime minister office", "pta",
    ],
    "pk_mobile_money": [
        "easypaisa", "jazzcash", "nayapay", "sadapay",
        "send easypaisa", "send jazzcash", "paisa bhejo",
        "number pe bhejo", "transfer karo",
    ],
    "pk_prize_scam": [
        "lucky draw", "prize bond winner", "sim lucky draw",
        "congratulations winner", "aap ne jeeta", "mobile jeeta",
        "car jeeta", "prize claim karo",
    ],
    "pk_bank_fraud": [
        "account band ho ga", "kyc update", "account verify",
        "bank se call", "otp share", "pin share nahi karna",
        "helpline number", "bank helpdesk",
    ],
}

# ── Post template patterns ────────────────────────────────────────────────────
POST_TEMPLATE_PATTERNS = [
    re.compile(r"send\s+\d*\.?\d+\s*(btc|eth|usdt|bnb|trx|sol|xrp)\s*(and|to)\s*(receive|get|earn)", re.I),
    re.compile(r"(guaranteed|100%)\s+(profit|returns?|income)", re.I),
    re.compile(r"(dm|message|inbox)\s+me\s+(now|today|for|to)", re.I),
    re.compile(r"limited\s+(slots?|spots?|offer|time)", re.I),
    re.compile(r"(join|click|tap)\s+(my\s+)?(telegram|whatsapp|channel|group|link)", re.I),
    re.compile(r"(make|earn)\s+\$[\d,]+\s+(per\s+)?(day|week|month)", re.I),
    re.compile(r"investment\s+of\s+\$?\d+\s+(returns?|gives?|yields?)", re.I),
    re.compile(r"(withdraw|withdrawal)\s+(proof|screenshot|evidence)", re.I),
    re.compile(r"(my\s+)?signals?\s+(group|channel|plan)\s+(is\s+)?(free|open|available)", re.I),
    re.compile(r"(zero|no)\s+risk\s+(trading|investment|profit)", re.I),
    re.compile(r"(10x|20x|50x|100x)\s+(your\s+)?(money|investment|profit|bitcoin)", re.I),
    re.compile(r"(passive|residual)\s+income\s+(of\s+)?\$?[\d,]+", re.I),
    re.compile(r"forex\s+(signal|alert|tip|strategy)\s+(provider|expert|master)", re.I),
    re.compile(r"(congratulations?|congrats?).{0,30}(winner|won|selected|chosen)", re.I),
]

# ── Engagement bait patterns ──────────────────────────────────────────────────
ENGAGEMENT_BAIT_PATTERNS = [
    re.compile(r"like\s+if\s+you\s+(agree|love|want|hate)", re.I),
    re.compile(r"tag\s+(a\s+)?(friend|someone|your\s+bestie)", re.I),
    re.compile(r"(comment|type)\s+(yes|amen|fire|agree)\s+if", re.I),
    re.compile(r"share\s+(this|if)\s+(to|you)", re.I),
    re.compile(r"follow\s+(for\s+follow|back|me\s+back)", re.I),
    re.compile(r"retweet\s+(if|and|to)", re.I),
]

# ── Scheduler / bot tools ─────────────────────────────────────────────────────
SCHEDULER_APPS = {
    "buffer", "hootsuite", "later", "sproutsocial", "sendible",
    "tweetdeck", "hypefury", "metricool", "recurpost", "agorapulse",
    "publer", "socialoomph", "zoho social", "loomly",
}

# ── Suspicious link services ──────────────────────────────────────────────────
SUSPICIOUS_LINK_SERVICES = {
    "t.me", "wa.me", "telegram.me", "telegram.org",
    "bit.ly", "tinyurl.com", "shorturl.at", "cutt.ly",
    "rb.gy", "ow.ly", "buff.ly", "is.gd", "v.gd", "clck.ru",
}

HIGH_RISK_LINK_SERVICES = {
    "t.me", "wa.me", "telegram.me",
    "clck.ru", "clck.cc", "grabify.link",
}

# ── Lookalike brand domains ───────────────────────────────────────────────────
LOOKALIKE_BRANDS = [
    "paypal", "amazon", "google", "facebook", "instagram", "twitter",
    "microsoft", "apple", "netflix", "ebay", "walmart", "chase",
    "bankofamerica", "wellsfargo", "citibank", "hsbc", "barclays",
    "coinbase", "binance", "kraken", "metamask", "trustwallet",
    "visa", "mastercard", "americanexpress", "blockchain",
    "nadra", "fbr", "fia", "hbl", "mcb", "ubl", "jazzcash", "easypaisa",
    "whatsapp", "telegram", "tiktok", "youtube", "linkedin",
    "dropbox", "adobe", "yahoo", "gmail", "outlook",
]

PHISHING_PATH_KEYWORDS = [
    "secure-login", "verify-account", "confirm-identity", "claim-prize",
    "account-suspended", "update-payment", "unusual-activity",
    "reset-password", "verify-email", "wallet-connect",
    "account-unlock", "claim-reward", "free-gift", "redeem-now",
    "login-verify", "security-update", "authentication",
]

# ── Geographic language map ───────────────────────────────────────────────────
GEO_LANG_MAP = {
    "pakistan":       {"arabic", "latin", "urdu"},
    "india":          {"latin", "devanagari", "tamil", "telugu"},
    "saudi arabia":   {"arabic"},
    "uae":            {"arabic", "latin"},
    "egypt":          {"arabic"},
    "iran":           {"arabic"},   # Perso-Arabic
    "turkey":         {"latin"},
    "russia":         {"cyrillic"},
    "china":          {"han"},
    "japan":          {"hiragana", "katakana", "han"},
    "korea":          {"hangul"},
    "usa":            {"latin"},
    "uk":             {"latin"},
    "france":         {"latin"},
    "germany":        {"latin"},
    "spain":          {"latin"},
    "brazil":         {"latin"},
    "bangladesh":     {"arabic", "latin"},
    "nigeria":        {"latin"},
    "ghana":          {"latin"},
    "malaysia":       {"latin", "arabic"},
    "indonesia":      {"latin", "arabic"},
}

SCRIPT_RANGES = {
    "arabic":     (0x0600, 0x06FF),
    "latin":      (0x0041, 0x024F),
    "cyrillic":   (0x0400, 0x04FF),
    "devanagari": (0x0900, 0x097F),
    "han":        (0x4E00, 0x9FFF),
    "hiragana":   (0x3040, 0x309F),
    "katakana":   (0x30A0, 0x30FF),
    "hangul":     (0xAC00, 0xD7AF),
    "tamil":      (0x0B80, 0x0BFF),
    "telugu":     (0x0C00, 0x0C7F),
    "thai":       (0x0E00, 0x0E7F),
    "hebrew":     (0x0590, 0x05FF),
}

# ── Crypto wallet regexes ─────────────────────────────────────────────────────
CRYPTO_WALLET_RE = re.compile(
    r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}"           # Bitcoin
    r"|0x[a-fA-F0-9]{40}"                              # Ethereum
    r"|T[a-zA-Z0-9]{33}"                               # Tron USDT
    r"|[LM3][a-zA-Z0-9]{25,33}"                        # Litecoin
    r"\b",
    re.ASCII,
)

# ── Phone regex (Pakistan + international) ────────────────────────────────────
PHONE_RE = re.compile(
    r"(\+92|0092|92|0)[-.\s]?3[0-9]{2}[-.\s]?[0-9]{7}"  # PK mobile
    r"|\+?[1-9]\d{7,14}",                                  # International
    re.ASCII,
)

# ── URL extraction ────────────────────────────────────────────────────────────
URL_RE = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    re.I,
)

# ── Emoji ─────────────────────────────────────────────────────────────────────
EMOJI_RE = re.compile(
    "[\U00002600-\U000027BF\U0001F300-\U0001F9FF"
    "\U0001FA00-\U0001FA9F\U00002702-\U000027B0]+",
    re.UNICODE,
)

# ── Username suspicious patterns ──────────────────────────────────────────────
RANDOM_USERNAME_RE = re.compile(r"[a-z]{4,8}\d{5,}$", re.I)
LEET_IMPERSONATION_RE = re.compile(
    r"(0fficial|0ficial|offici4l|0ffici4l|verif1ed|verifi3d)", re.I
)

# ── Platform engagement benchmarks ───────────────────────────────────────────
ENGAGEMENT_BENCHMARKS = {
    "instagram": {"micro": 3.86, "small": 2.85, "medium": 1.97, "large": 1.21, "mega": 0.70},
    "twitter":   {"micro": 1.60, "small": 0.98, "medium": 0.50, "large": 0.28, "mega": 0.10},
    "tiktok":    {"micro": 8.80, "small": 5.30, "medium": 3.50, "large": 2.10, "mega": 1.00},
    "facebook":  {"micro": 1.20, "small": 0.87, "medium": 0.55, "large": 0.35, "mega": 0.20},
    "youtube":   {"micro": 4.00, "small": 2.60, "medium": 1.80, "large": 1.20, "mega": 0.80},
    "linkedin":  {"micro": 2.00, "small": 1.50, "medium": 0.90, "large": 0.50, "mega": 0.30},
    "default":   {"micro": 2.00, "small": 1.50, "medium": 0.80, "large": 0.40, "mega": 0.20},
}

# ── Sherlock-style platform URL templates ─────────────────────────────────────
PLATFORM_URLS = {
    "twitter":    "https://twitter.com/{u}",
    "instagram":  "https://www.instagram.com/{u}/",
    "tiktok":     "https://www.tiktok.com/@{u}",
    "facebook":   "https://www.facebook.com/{u}",
    "youtube":    "https://www.youtube.com/@{u}",
    "linkedin":   "https://www.linkedin.com/in/{u}",
    "snapchat":   "https://www.snapchat.com/add/{u}",
    "pinterest":  "https://www.pinterest.com/{u}/",
    "reddit":     "https://www.reddit.com/user/{u}",
    "twitch":     "https://www.twitch.tv/{u}",
    "github":     "https://github.com/{u}",
    "gitlab":     "https://gitlab.com/{u}",
    "medium":     "https://medium.com/@{u}",
    "telegram":   "https://t.me/{u}",
    "steam":      "https://steamcommunity.com/id/{u}",
    "deviantart": "https://{u}.deviantart.com",
    "tumblr":     "https://{u}.tumblr.com",
    "soundcloud": "https://soundcloud.com/{u}",
    "vimeo":      "https://vimeo.com/{u}",
    "behance":    "https://www.behance.net/{u}",
    "dribbble":   "https://dribbble.com/{u}",
    "quora":      "https://www.quora.com/profile/{u}",
    "linktree":   "https://linktr.ee/{u}",
    "keybase":    "https://keybase.io/{u}",
    "mastodon":   "https://mastodon.social/@{u}",
    "codepen":    "https://codepen.io/{u}",
    "replit":     "https://replit.com/@{u}",
    "kaggle":     "https://www.kaggle.com/{u}",
}

# ── Roman Urdu common words ───────────────────────────────────────────────────
ROMAN_URDU_MARKERS = {
    "acha", "theek", "nahi", "haan", "yaar", "bhai", "yeh", "kya",
    "karo", "mujhe", "tum", "aap", "lekin", "magar", "phir", "abhi",
    "kal", "aj", "aaj", "raat", "subah", "paise", "rupay", "zindagi",
    "dost", "pyar", "ishq", "masla", "koi", "sab", "bas", "bohot",
    "bahut", "zyada", "kam", "accha", "theek", "bilkul", "zaroor",
}
