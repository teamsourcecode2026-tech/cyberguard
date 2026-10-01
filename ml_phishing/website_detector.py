import requests
from bs4 import BeautifulSoup
from url_detector import analyze_url_phishing

KNOWN_BRANDS = ["google", "paypal", "amazon", "microsoft", "apple", "facebook", "netflix", "bankofamerica"]


def fetch_page(url: str, timeout: int = 5):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        response = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        return response
    except requests.RequestException:
        return None


def has_login_form(soup) -> bool:
    forms = soup.find_all("form")
    for form in forms:
        inputs = form.find_all("input")
        types = [inp.get("type", "").lower() for inp in inputs]
        if "password" in types:
            return True
    return False


def mentions_brand_without_being_it(page_text: str, domain: str) -> str | None:
    lowered_text = page_text.lower()
    for brand in KNOWN_BRANDS:
        if brand not in domain.lower() and lowered_text.count(brand) >= 5:
            return brand
    return None


def analyze_website_phishing(url: str) -> dict:
    result = analyze_url_phishing(url)

    response = fetch_page(url)

    if response is None:
        result["indicators"].append("Website could not be reached (may be offline or blocking automated checks)")
        return result

    if not response.url.startswith("https://"):
        result["indicators"].append("Website does not use HTTPS (no secure connection)")

    soup = BeautifulSoup(response.text, "html.parser")

    if has_login_form(soup):
        result["indicators"].append("Page contains a login form requesting a password")

    page_text = soup.get_text()
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    impersonated_brand = mentions_brand_without_being_it(page_text, domain)
    if impersonated_brand:
        result["indicators"].append(f"Page content mentions '{impersonated_brand}' but domain does not match")

    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    if title and impersonated_brand and impersonated_brand not in title.lower():
        result["indicators"].append("Page title does not match the brand it claims to represent")

    return result