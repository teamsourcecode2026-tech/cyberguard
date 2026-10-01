import requests
from urllib.parse import urlparse
from model_loader import score_text

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".info", ".tk", ".gq", ".loan", ".win"]


def get_domain(url: str) -> str:
    return urlparse(url).netloc.split(":")[0].lower()


def follow_redirects(url: str, timeout: int = 5):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        response = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        chain = [r.url for r in response.history] + [response.url]
        return chain
    except requests.RequestException:
        return None


def analyze_malicious_redirect(url: str) -> dict:
    full_url = url if "://" in url else f"http://{url}"
    indicators = []

    chain = follow_redirects(full_url)

    if chain is None:
        indicators.append("Could not reach URL to check for redirects (may be offline or blocking automated checks)")
        base_score = round(score_text(full_url) * 100)
        return {"score": base_score, "verdict": "Suspicious" if base_score >= 40 else "Safe", "indicators": indicators}

    original_domain = get_domain(chain[0])
    final_domain = get_domain(chain[-1])
    redirect_count = len(chain) - 1

    if redirect_count > 0 and original_domain != final_domain:
        indicators.append(f"Redirects from '{original_domain}' to a different domain: '{final_domain}'")

    if redirect_count >= 3:
        indicators.append(f"URL redirects through an unusually long chain ({redirect_count} hops)")

    if any(final_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        indicators.append(f"Final redirect destination uses a high-risk domain extension ({final_domain.split('.')[-1]})")

    if not chain[-1].startswith("https://"):
        indicators.append("Final redirect destination does not use HTTPS")

    base_score = round(score_text(chain[-1]) * 100)
    score = min(100, base_score + 20 * len(indicators))

    if score >= 70:
        verdict = "Phishing"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    if not indicators:
        indicators.append("No suspicious redirect behavior detected")

    return {"score": score, "verdict": verdict, "indicators": indicators}