from model import analyze_phishing

GIVEAWAY_WORDS = ["giveaway", "you've been selected", "claim your prize", "free followers", "verified badge"]
SUSPENSION_WORDS = ["account suspended", "account will be disabled", "violated community guidelines", "confirm your account"]
MOVE_OFF_PLATFORM_WORDS = ["message me on whatsapp", "contact me on telegram", "reach me at this number", "dm me on"]
CRYPTO_ROMANCE_WORDS = ["investment opportunity", "double your bitcoin", "crypto trading", "send me gift cards", "i love you", "lonely"]
IMPERSONATION_WORDS = ["official support team", "this is instagram support", "facebook security team", "verified account team"]


def analyze_social_media_phishing(text: str) -> dict:
    result = analyze_phishing(text)
    lowered = text.lower()

    if any(word in lowered for word in GIVEAWAY_WORDS):
        result["indicators"].append("Impersonates a fake giveaway or prize scam")

    if any(word in lowered for word in SUSPENSION_WORDS):
        result["indicators"].append("Impersonates account suspension/verification threat")

    if any(word in lowered for word in MOVE_OFF_PLATFORM_WORDS):
        result["indicators"].append("Attempts to move conversation to another platform")

    if any(word in lowered for word in CRYPTO_ROMANCE_WORDS):
        result["indicators"].append("Contains crypto investment or romance scam language")

    if any(word in lowered for word in IMPERSONATION_WORDS):
        result["indicators"].append("Impersonates official platform support/security team")

    return result