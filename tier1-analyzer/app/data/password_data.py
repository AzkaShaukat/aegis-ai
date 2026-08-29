"""
Embedded data for password and username analysis.
"""

# ── Top 2000 most common passwords ────────────────────────────────────────────
COMMON_PASSWORDS: set = {
    "password","password1","password123","123456","123456789","12345678",
    "1234567","1234567890","qwerty","abc123","monkey","1234","dragon",
    "master","sunshine","princess","welcome","shadow","superman","michael",
    "jessica","letmein","trustno1","batman","football","iloveyou","admin",
    "login","hello","charlie","donald","password2","qwerty123","1q2w3e",
    "q1w2e3r4","123qwe","111111","000000","121212","123123","696969",
    "654321","987654321","pass","test","guest","root","toor","changeme",
    "secret","pass123","pass1234","passw0rd","p@ssw0rd","p@ss0word",
    "1111111111","00000000","987654","aaaaaa","abc123456","abcdef",
    "abcdefg","qazwsx","qazwsxedc","1qaz2wsx","zxcvbnm","asdfgh",
    "asdfghjkl","zxcvbn","poiuytrewq","lkjhgfdsa","mnbvcxz",
    "password!","password@","Password1","Password123","Pa$$word",
    "P@ssword","P@ssw0rd","P@$$w0rd","1234abcd","abcd1234","a1b2c3d4",
    "love","god","sex","money","fuck","shit","ass","porn","hot","cool",
    "star","blue","red","black","white","green","yellow","pink","gold",
    "silver","fire","ice","air","rock","stone","earth","sky","sun","moon",
    "king","queen","prince","angel","devil","heaven","hell","life","death",
    # Pakistani common patterns
    "pakistan","lahore","karachi","islamabad","rawalpindi","peshawar",
    "quetta","multan","faisalabad","hyderabad","gujranwala","sialkot",
    "ahmed","ali","muhammad","mohammad","hassan","hussain","khan","malik",
    "iqbal","jinnah","imran","nawaz","sharif","bhutto","zardari",
    "pakistan1","pakistan123","lahore123","karachi123","islamabad1",
    "786786","786","1947","1971","14august","23march","6september",
    # Generic patterns
    "summer","winter","spring","autumn","january","february","march",
    "april","may","june","july","august","september","october","november","december",
    "monday","tuesday","wednesday","thursday","friday","saturday","sunday",
    "2020","2021","2022","2023","2024","2025","1990","1991","1992","1993",
    "1994","1995","1996","1997","1998","1999","2000","2001","2002","2003",
    "mypassword","mypass","myname","myfamily","mycat","mydog",
    "iloveyou1","iloveme","ilovehim","ilovehim1","iloveyoubaby",
    "qwerty1","qwerty12","qwerty1234","qwertyuiop","qwertyui",
    "1234567890","12345","1234","123","12","1","0","00","000",
    "internet","computer","windows","linux","android","apple","iphone",
    "google","facebook","twitter","instagram","whatsapp","telegram",
    "cricket","football","hockey","tennis","basketball","swimming",
    "tiger","lion","eagle","wolf","bear","shark","cobra","viper",
    "nike","adidas","puma","gucci","armani","versace","ferrari","lamborghini",
    "matrix","batman1","spiderman","superman1","avengers","marvel","dc",
    "harley","davidson","yamaha","honda","toyota","suzuki","kawasaki",
}

# ── Urdu Roman wordlist ────────────────────────────────────────────────────────
URDU_ROMAN: set = {
    "pakistan","lahore","karachi","islamabad","peshawar","quetta","rawalpindi",
    "multan","faisalabad","hyderabad","gujranwala","sialkot","sargodha",
    "bahawalpur","sukkur","larkana","sheikhupura","jhang","chiniot","gujrat",
    "iqbal","jinnah","quaid","liaquat","khan","malik","chaudhry","rajput",
    "pasha","baig","qureshi","siddiqui","farooqi","hashmi","bukhari",
    "ahmed","ali","hassan","hussain","fatima","maryam","zainab","ayesha",
    "muhammad","mohammad","muhamad","mehmed","mohd","mhmd",
    "allah","bismillah","alhamdulillah","mashallah","inshallah","subhanallah",
    "ramzan","eid","jumma","salah","namaz","roza","hajj","zakat","fitra",
    "pyar","ishq","mohabbat","dil","yaar","dost","bhai","behan","maa","baba",
    "apna","apni","mera","meri","hamara","tumhara","tera","teri",
    "zindagi","duniya","khuda","takdir","qismat","naseeb","waqt",
    "khana","paani","chai","biryani","karahi","nihari","halwa","puri",
    "rupee","paisay","hajar","lakh","crore","Arab",
    "haan","nahi","theek","accha","bahut","thoda","zyada","kam",
    "jaldi","aaramse","aaj","kal","parso","abhi","pehle","baad",
    "ghar","kamra","darwaza","khirkhi","chhat","zameen","aasman",
    "sher","bagh","hiran","murgha","gaay","bhed","bakri","machhli",
    "school","college","university","madrasa","kitab","qalam","copy",
    "dost","yaar","bhai","behen","ammi","abbu","dada","dadi","nana","nani",
    "786","allah786","786pak","pak786",
}

# ── Leetspeak substitution map (l33t → normal) ────────────────────────────────
LEET_MAP: dict = {
    '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g',
    '@': 'a', '$': 's', '!': 'i', '+': 't', '#': 'h',
    '|': 'i', '(': 'c', ')': 'o', '[': 'c', ']': 'o',
    '{': 'c', '}': 'o', '<': 'c', '>': 'o', '^': 'a',
    '&': 'and', '%': 'percent', '*': 'x',
}

# ── Keyboard adjacency maps ────────────────────────────────────────────────────
QWERTY_ADJACENCY: dict = {
    'q': ['w','a','s'],     'w': ['q','e','a','s','d'],
    'e': ['w','r','s','d','f'], 'r': ['e','t','d','f','g'],
    't': ['r','y','f','g','h'], 'y': ['t','u','g','h','j'],
    'u': ['y','i','h','j','k'], 'i': ['u','o','j','k','l'],
    'o': ['i','p','k','l'],     'p': ['o','l'],
    'a': ['q','w','s','z'],     's': ['a','w','e','d','z','x'],
    'd': ['s','e','r','f','x','c'], 'f': ['d','r','t','g','c','v'],
    'g': ['f','t','y','h','v','b'], 'h': ['g','y','u','j','b','n'],
    'j': ['h','u','i','k','n','m'], 'k': ['j','i','o','l','m'],
    'l': ['k','o','p'],
    'z': ['a','s','x'],     'x': ['z','s','d','c'],
    'c': ['x','d','f','v'], 'v': ['c','f','g','b'],
    'b': ['v','g','h','n'], 'n': ['b','h','j','m'],
    'm': ['n','j','k'],
    '1': ['2','q'],  '2': ['1','3','q','w'], '3': ['2','4','w','e'],
    '4': ['3','5','e','r'], '5': ['4','6','r','t'], '6': ['5','7','t','y'],
    '7': ['6','8','y','u'], '8': ['7','9','u','i'], '9': ['8','0','i','o'],
    '0': ['9','o','p'],
}

COMMON_WALKS: list = [
    "qwerty","qwertyuiop","asdfgh","asdfghjkl","zxcvbn","zxcvbnm",
    "1234567890","0987654321","1234","12345","123456","1234567","12345678",
    "qweasdzxc","qazwsxedc","1qaz2wsx","1qaz2wsx3edc",
    "poiuytrewq","lkjhgfdsa","mnbvcxz",
    "qweasd","asdzxc","wsxedc","edcrfv","rfvtgb","tgbyhn","yhnujm",
    "qazxsw","qazxswedcvfr","!@#$%^&*()",
]

# ── Email homoglyphs ───────────────────────────────────────────────────────────
HOMOGLYPH_MAP: dict = {
    # Cyrillic → Latin
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'у': 'y', 'х': 'x', 'В': 'B', 'Е': 'E', 'К': 'K',
    'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C',
    'Т': 'T', 'Х': 'X', 'А': 'A', 'Ь': 'b',
    # Greek → Latin
    'α': 'a', 'β': 'b', 'ε': 'e', 'ο': 'o', 'ρ': 'p',
    'τ': 't', 'υ': 'u', 'χ': 'x', 'ν': 'v', 'κ': 'k',
    # Latin lookalikes
    'ı': 'i',  # Turkish dotless i
    'ḷ': 'l',  # l with dot below
    'ṁ': 'm',  # m with dot
    'ṅ': 'n',  # n with dot
    'ọ': 'o',  # o with dot below
    'ṗ': 'p',  # p with dot
    'ṙ': 'r',  # r with dot
    'ṡ': 's',  # s with dot
    'ṭ': 't',  # t with dot below
    'ụ': 'u',  # u with dot below
    'ẉ': 'w',  # w with dot below
    # Zero-width / special
    '\u200b': '',  # zero-width space
    '\u200c': '',  # zero-width non-joiner
    '\u200d': '',  # zero-width joiner
    '\ufeff': '',  # BOM
}

# ── Brand list for impersonation detection ────────────────────────────────────
BRANDS: list = [
    # Global tech & finance
    "paypal","amazon","google","microsoft","apple","facebook","instagram",
    "twitter","netflix","spotify","ebay","alibaba","visa","mastercard",
    "amex","americanexpress","venmo","cashapp","zelle","chase","wellsfargo",
    "bankofamerica","citibank","barclays","hsbc","linkedin","dropbox",
    "adobe","oracle","salesforce","zoom","slack","discord","telegram",
    "whatsapp","signal","tiktok","snapchat","pinterest","reddit","youtube",
    "twitch","github","gitlab","bitbucket","stackoverflow","cloudflare",
    "godaddy","shopify","woocommerce","stripe","square","coinbase",
    "binance","kraken","metamask","blockchain","bitcoin","ethereum",
    # Pakistani banks & fintech
    "hbl","mcb","ubl","nbl","nbp","albaraka","askari","bankislami",
    "dubai","faysal","habibmetro","meezan","jsbank","bankalphalah",
    "alfalah","silkbank","samba","bankofpunjab","bop","pmcb",
    "jazzcash","easypaisa","nayapay","sadapay","upaisa","mobicash",
    "keenudhaar","tezpay","pakpos",
    # Telecom
    "jazz","zong","telenor","ufone","scom","ptcl","warid",
    "airtel","vodafone","att","tmobile","verizon","sprint",
    # Ecommerce PK
    "daraz","foodpanda","bykea","careem","uber","indriver",
    "olx","pakwheels","zameen","homeshopping","telemart","goto",
    # Government PK
    "nadra","fbr","pemra","secp","sbp","nhrc","fmc","pta",
    # Support / admin keywords
    "support","helpdesk","help","admin","administrator","service",
    "security","account","verify","official","staff","team",
    "customer","cs","customerservice","billing","payments",
]
