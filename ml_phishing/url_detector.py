import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
from model import analyze_phishing

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".info", ".tk", ".gq", ".loan", ".win"]
KNOWN_BRANDS = ["google", "paypal", "amazon", "microsoft", "apple", "facebook", "netflix", "bankofamerica"]


def is_ip_based(domain: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))


def has_suspicious_tld(domain: str) -> bool:
    return any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)


def has_excessive_subdomains(domain: str) -> bool:
    return domain.count(".") >= 3


def find_lookalike_brand(domain: str) -> str | None:
    main_part = domain.split(".")[0]
    for brand in KNOWN_BRANDS:
        similarity = SequenceMatcher(None, main_part, brand).ratio()
        if 0.75 <= similarity < 1.0:
            return brand
    return None


def analyze_url_phishing(url: str) -> dict:
    result = analyze_phishing(url)

    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.netloc.split(":")[0]
    ip_based = is_ip_based(domain)

    if ip_based:
        result["indicators"].append("URL uses a raw IP address instead of a domain name")
    else:
        if has_suspicious_tld(domain):
            result["indicators"].append(f"Uses an uncommon/high-risk domain extension ({domain.split('.')[-1]})")

        if has_excessive_subdomains(domain):
            result["indicators"].append("Unusually high number of subdomains")

        lookalike = find_lookalike_brand(domain)
        if lookalike:
            result["indicators"].append(f"Domain closely resembles '{lookalike}' but is not the real domain")

    if "@" in url:
        result["indicators"].append("Contains '@' symbol, often used to disguise the real destination")

    return result