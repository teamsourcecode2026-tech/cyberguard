import re
from urllib.parse import urlparse, parse_qs, unquote
from model_loader import score_text

KNOWN_BRANDS = ["google", "paypal", "amazon", "microsoft", "apple", "facebook", "netflix", "bankofamerica"]
REDIRECT_PARAM_NAMES = ["redirect", "url", "next", "dest", "destination", "continue", "return", "goto"]


def has_at_symbol_disguise(url: str) -> bool:
    before_path = url.split("://")[-1].split("/")[0]
    return "@" in before_path


def find_open_redirect_param(url: str):
    query = urlparse(url).query
    params = parse_qs(query)
    for param_name in REDIRECT_PARAM_NAMES:
        if param_name in params:
            value = params[param_name][0]
            if value.startswith(("http://", "https://", "//")):
                return param_name, value
    return None


def has_excessive_encoding(url: str) -> bool:
    encoded_count = url.count("%")
    return encoded_count >= 4


def find_brand_in_path(url: str):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    for brand in KNOWN_BRANDS:
        if brand in path and brand not in domain:
            return brand
    return None


def analyze_url_manipulation(url: str) -> dict:
    full_url = url if "://" in url else f"http://{url}"
    decoded_url = unquote(full_url)

    indicators = []

    if has_at_symbol_disguise(full_url):
        indicators.append("Contains '@' symbol before the real domain \u2014 common disguise technique")

    redirect = find_open_redirect_param(full_url)
    if redirect:
        param_name, target = redirect
        indicators.append(f"Contains an open-redirect parameter ('{param_name}') pointing to another URL: {target[:50]}")

    if has_excessive_encoding(full_url):
        indicators.append("URL contains excessive percent-encoding, possibly hiding its real destination")

    brand_in_path = find_brand_in_path(decoded_url)
    if brand_in_path:
        indicators.append(f"Brand name '{brand_in_path}' appears in the URL path, not the actual domain \u2014 likely meant to confuse")

    base_score = round(score_text(full_url) * 100)
    score = min(100, base_score + 20 * len(indicators))

    if score >= 70:
        verdict = "Phishing"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    if not indicators:
        indicators.append("No URL manipulation patterns detected")

    return {"score": score, "verdict": verdict, "indicators": indicators}