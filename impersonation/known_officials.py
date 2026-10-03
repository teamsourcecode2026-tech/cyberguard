# impersonation/known_officials.py
# Small reference set for demo purposes. In production this would be
# a verified government directory / API, not a hardcoded list.

KNOWN_OFFICIALS = [
    {"name": "Narendra Modi", "title": "Prime Minister of India"},
    {"name": "Droupadi Murmu", "title": "President of India"},
    {"name": "Amit Shah", "title": "Minister of Home Affairs"},
]

OFFICIAL_TITLE_KEYWORDS = [
    "minister", "prime minister", "president", "governor", "collector",
    "commissioner", "ias officer", "ips officer", "chief secretary",
    "district magistrate", "police commissioner",
]

SCAM_PHRASES = [
    "pay immediately", "arrest warrant", "share otp", "verify your account",
    "account will be blocked", "legal action will be taken", "pending fine",
    "click this link to avoid", "urgent action required", "confidential matter",
    "transfer the amount", "processing fee", "customs duty pending",
]

OFFICIAL_EMAIL_DOMAINS = ["gov.in", "nic.in"]
SENIOR_MANAGEMENT = [
    # Sample data for demo purposes - in production this would come
    # from your organization's verified employee directory.
    {"name": "Ratan Tata", "title": "Chairman"},
    {"name": "Mukesh Ambani", "title": "CEO"},
]

MANAGEMENT_TITLE_KEYWORDS = [
    "ceo", "chief executive officer", "cfo", "chief financial officer",
    "coo", "chief operating officer", "managing director", "chairman",
    "vice president", "vp", "founder", "president of the company",
]

CEO_FRAUD_PHRASES = [
    "wire transfer", "gift cards", "need this done urgently", "can't talk right now",
    "keep this confidential", "don't tell anyone", "buy gift cards", "send the funds",
    "i'm in a meeting", "trust you to handle this", "this is time sensitive",
    "bypass the usual process", "handle this discreetly",
]