import re
from difflib import SequenceMatcher
from urllib.parse import urlparse
from model_loader import score_text

KNOWN_BRANDS = ["google", "paypal", "amazon", "microsoft", "apple", "facebook", "netflix", "bankofamerica"]
KNOWN_BRAND_DOMAINS = {
    "google": "google.com", "paypal": "paypal.com", "amazon": "amazon.com",
    "microsoft": "microsoft.com", "apple": "apple.com", "facebook": "facebook.com",
    "netflix": "netflix.com", "bankofamerica": "bankofamerica.com"
}


def decode_punycode_domain(domain: str) -> str:
    labels = domain.split(".")
    decoded = []
    for label in labels:
        if label.startswith("xn--"):
            try:
                decoded.append(label.encode("ascii").decode("idna"))
            except Exception:
                decoded.append(label)
        else:
            decoded.append(label)
    return ".".join(decoded)


def is_punycode_domain(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.split("."))


def find_typosquat(main_label: str):
    for brand in KNOWN_BRANDS:
        similarity = SequenceMatcher(None, main_label, brand).ratio()
        if 0.75 <= similarity < 1.0:
            return brand, similarity
    return None


def find_combosquat(main_label: str):
    for brand in KNOWN_BRANDS:
        if brand in main_label and main_label != brand:
            return brand
    return None


def find_subdomain_spoof(domain: str):
    labels = domain.split(".")
    if len(labels) < 3:
        return None
    main_domain = ".".join(labels[-2:])
    for brand in KNOWN_BRANDS:
        brand_domain = KNOWN_BRAND_DOMAINS.get(brand)
        if brand_domain and brand_domain != main_domain:
            for label in labels[:-2]:
                if brand in label:
                    return brand
    return None


def analyze_domain_spoofing(url: str) -> dict:
    full_url = url if "://" in url else f"http://{url}"
    domain = urlparse(full_url).netloc.split(":")[0].lower()
    labels = domain.split(".")
    main_label = labels[-2] if len(labels) >= 2 else domain

    indicators = []

    if is_punycode_domain(domain):
        decoded = decode_punycode_domain(domain)
        indicators.append(f"Domain uses punycode encoding, possible homograph attack (decodes to '{decoded}')")

    typo = find_typosquat(main_label)
    if typo:
        brand, similarity = typo
        indicators.append(f"Domain closely resembles '{brand}' ({similarity:.0%} similar) \u2014 possible typosquatting")

    combo = find_combosquat(main_label)
    if combo and not typo:
        indicators.append(f"Brand name '{combo}' combined with extra words in domain \u2014 possible combosquatting")

    subspoof = find_subdomain_spoof(domain)
    if subspoof:
        indicators.append(f"Brand name '{subspoof}' used as a subdomain, not the real domain \u2014 possible subdomain spoofing")

    base_score = round(score_text(full_url) * 100)
    score = min(100, base_score + 20 * len(indicators))

    if score >= 70:
        verdict = "Phishing"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    if not indicators:
        indicators.append("No domain spoofing patterns detected")

    return {"score": score, "verdict": verdict, "indicators": indicators}