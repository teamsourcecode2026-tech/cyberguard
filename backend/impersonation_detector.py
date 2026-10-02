# Shared "ask" phrases — these signal someone wants you to DO something urgently.
# Used alongside every identity category below.
URGENT_ASK_PHRASES = [
    "pay immediately", "send otp", "share your otp", "verify your account",
    "click the link", "call back immediately", "provide your pan", "provide your aadhaar", "pay customs duty", "your sim will be deactivated", "confirm your delivery address",
    "your parcel is on hold",
    "transfer the amount", "buy gift cards", "your result will be withheld", "you will be marked absent", "your degree will be cancelled",
    "pay the pending fee", "submit your documents immediately", "your admission will be cancelled", "purchase gift cards", "wire the funds", "keep this confidential",
    "don't discuss this with anyone", "handle this discreetly", "settle the fine", "blocked your account", "arrest warrant",
    "legal action will be taken", "urgent action required", "don't tell anyone about this", "update your kyc", "your card will be blocked",
]

# Category 1: Government officials
GOVERNMENT_PHRASES = [
    "income tax department", "this is the police", "cyber crime cell", "reserve bank of india",
    "customs department", "court notice", "government of india", "cbi officer",
    "enforcement directorate", "passport office"
]
# Category 2: Senior management
MANAGEMENT_PHRASES = [
    "this is your ceo", "message from the managing director", "i am your manager",
    "on behalf of the director", "this is hr department", "urgent from management",
    "ceo here", "boss here", "need this done quietly",
    "confidential request from leadership", "this is your supervisor"
]
# Category 3: Teachers or university authorities
EDUCATION_PHRASES = [
    "this is your professor", "university administration", "exam cell", "your college principal",
    "hod office", "this is your hostel warden", "controller of examinations", "this is your academic advisor",
    "registrar office", "dean of students"
]
# Category 4: Financial institutions
FINANCIAL_PHRASES = [
    "this is your bank", "state bank of india", "hdfc bank", "icici bank", "axis bank",
    "kotak bank", "this is paytm support", "this is phonepe support", "this is google pay support",
    "credit card department", "loan department", "your bank manager", "rbi guidelines",
    "kyc update required", "your debit card"
]
# Category 5: Organisations or brands
ORGANISATION_PHRASES = [
    "this is amazon support", "this is flipkart support", "delivery department",
    "this is your courier company", "this is bluedart", "this is dtdc", "customs clearance",
    "this is jio", "this is airtel", "this is vodafone idea", "sim card department",
    "this is netflix support", "this is microsoft support", "this is your telecom provider"
]
# Category 6: Friends, relatives, or known contacts
KNOWN_CONTACT_SCENARIO_PHRASES = [
    "this is my new number", "lost my phone", "my phone is damaged", "using a friend's phone",
    "don't tell mom", "don't tell dad", "it's me, your son", "it's me, your daughter",
    "save this number", "my old number is not working", "stuck somewhere", "need money urgently",
    "send money right now", "i am in trouble", "hospital emergency", "can you send some money"
]

def _count_matches(text_lower, phrase_list):
    return [p for p in phrase_list if p in text_lower]

def analyze_impersonation(text: str) -> dict:
    text_lower = text.lower()

    identity_hits = _count_matches(text_lower, GOVERNMENT_PHRASES + MANAGEMENT_PHRASES + EDUCATION_PHRASES + FINANCIAL_PHRASES + ORGANISATION_PHRASES)
    ask_hits = _count_matches(text_lower, URGENT_ASK_PHRASES)

    indicators = []
    score = 0

    if identity_hits:
        indicators.append(f"claims to be: {', '.join(identity_hits)}")
        score += 40
    if ask_hits:
        indicators.append(f"urgent request: {', '.join(ask_hits)}")
        score += 40
    if identity_hits and ask_hits:
        score += 20  # both together is the real signal
    contact_hits = _count_matches(text_lower, KNOWN_CONTACT_SCENARIO_PHRASES)
    if contact_hits:
        indicators.append(f"known-contact scam pattern: {', '.join(contact_hits)}")
        score += 50
    if len(contact_hits) >= 2:
        score += 30  # two or more of these together is a strong signal
   
    score = min(score, 100)

    if score >= 70:
        verdict = "Likely Impersonation"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Low Risk"

    return {"score": score, "verdict": verdict, "indicators": indicators}