import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from model_loader import score_text

KNOWN_BRANDS = ["google", "paypal", "amazon", "microsoft", "apple", "facebook", "netflix", "bankofamerica"]


def fetch_page(url: str, timeout: int = 5):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        response = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        return response
    except requests.RequestException:
        return None


def find_login_forms(soup):
    login_forms = []
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        types = [inp.get("type", "").lower() for inp in inputs]
        if "password" in types:
            login_forms.append(form)
    return login_forms


def form_submits_off_domain(form, page_domain: str, page_url: str) -> bool:
    action = form.get("action", "")
    if not action:
        return False
    full_action_url = urljoin(page_url, action)
    action_domain = urlparse(full_action_url).netloc.split(":")[0].lower()
    return bool(action_domain) and action_domain != page_domain


def mentions_brand_prominently(soup, domain: str) -> str | None:
    title = soup.title.string.lower() if soup.title and soup.title.string else ""
    headings = " ".join(h.get_text().lower() for h in soup.find_all(["h1", "h2"]))
    prominent_text = title + " " + headings

    for brand in KNOWN_BRANDS:
        if brand in prominent_text and brand not in domain.lower():
            return brand
    return None


def analyze_fake_login(url: str) -> dict:
    full_url = url if "://" in url else f"http://{url}"
    domain = urlparse(full_url).netloc.split(":")[0].lower()

    response = fetch_page(full_url)
    if response is None:
        return {
            "score": 0,
            "verdict": "Safe",
            "indicators": ["Website could not be reached (may be offline or blocking automated checks)"]
        }

    indicators = []
    soup = BeautifulSoup(response.text, "html.parser")
    login_forms = find_login_forms(soup)

    if not login_forms:
        base_score = round(score_text(full_url) * 100)
        return {
            "score": base_score,
            "verdict": "Suspicious" if base_score >= 40 else "Safe",
            "indicators": ["No login form detected on this page"]
        }

    indicators.append("Page contains a login form requesting a password")

    if not response.url.startswith("https://"):
        indicators.append("Login form is on a page without HTTPS \u2014 credentials could be intercepted")

    for form in login_forms:
        if form_submits_off_domain(form, domain, response.url):
            indicators.append("Login form submits data to a different domain than the page itself")
            break

    brand = mentions_brand_prominently(soup, domain)
    if brand:
        indicators.append(f"Page prominently displays '{brand}' branding but domain does not match \u2014 likely impersonation")

    base_score = round(score_text(full_url) * 100)
    score = min(100, base_score + 25 * (len(indicators) - 1))

    if score >= 70:
        verdict = "Phishing"
    elif score >= 40:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {"score": score, "verdict": verdict, "indicators": indicators}