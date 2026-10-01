from urllib.parse import urlparse
from model_loader import score_text

KNOWN_BRANDS = ["google", "paypal", "amazon", "microsoft", "apple", "facebook", "netflix", "bankofamerica"]

SINGLE_CHAR_SUBSTITUTIONS = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "$": "s", "@": "a"
}

MULTI_CHAR_SUBSTITUTIONS = {
    "rn": "m", "vv": "w", "cl": "d", "ii": "u"
}


def normalize_domain_label(label: str) -> str:
    normalized = label
    for fake, real in MULTI_CHAR_SUBSTITUTIONS.items():
        normalized = normalized.replace(fake, real)
    for fake, real in SINGLE_CHAR_SUBSTITUTIONS.items():
        normalized = normalized.replace(fake, real)
    return normalized


def find_lookalike_substitution(main_label: str):
    normalized = normalize_domain_label(main_label)
    if normalized == main_label:
        return None
    for brand in KNOWN_BRANDS:
        if normalized == brand:
            return brand
    return None


def analyze_lookalike_domain(url: str) -> dict:
    full_url = url if "://" in url else f"http://{url}"
    domain = urlparse(full_url).netloc.split(":")[0].lower()
    labels = domain.split(".")
    main_label = labels[-2] if len(labels) >= 2 else domain

    indicators = []
    lookalike = find_lookalike_substitution(main_label)

    if lookalike:
        indicators.append(
            f"Domain '{main_label}' uses character substitution to mimic '{lookalike}' "
            f"(e.g. 0\u2192o, 1\u2192l, rn\u2192m)"
        )

    base_score = round(score_text(full_url) * 100)
    score = min(100, base_score + (35 if lookalike else 0))

    if score >= 70:
        verdict = "Phishing"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    if not indicators:
        indicators.append("No character-substitution lookalike patterns detected")

    return {"score": score, "verdict": verdict, "indicators": indicators}